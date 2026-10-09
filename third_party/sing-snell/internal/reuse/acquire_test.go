package reuse

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type acquisition struct {
	session *testSession
	reused  bool
	err     error
}

func acquireAsync(p *Pool[*testSession], ctx context.Context, dial func(context.Context) (*testSession, error)) <-chan acquisition {
	result := make(chan acquisition, 1)
	go func() {
		s, r, err := p.Acquire(ctx, dial)
		result <- acquisition{s, r, err}
	}()
	return result
}

func await[T any](t *testing.T, c <-chan T) T {
	t.Helper()
	select {
	case v := <-c:
		return v
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for acquisition event")
		var zero T
		return zero
	}
}

func awaitClosed(t *testing.T, s *testSession) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for s.closed.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := s.closed.Load(); got != 1 {
		t.Fatalf("abandoned dial closed %d times", got)
	}
}

func TestAcquireReadyDoesNotDial(t *testing.T) {
	p := makePool(t)
	want := put(t, p, StateReady)
	got, reused, err := p.Acquire(context.Background(), func(context.Context) (*testSession, error) {
		t.Error("ready pool hit started a dial")
		return nil, errors.New("unexpected dial")
	})
	if err != nil || !reused || got != want {
		t.Fatalf("result = %v, %v, %v", got, reused, err)
	}
	if State(got.state.Load()) != StateActive {
		t.Fatal("pooled session not exclusively reserved")
	}
	got.Close()
}

func TestAcquireDrainedSessionCancelsAndClosesLateDial(t *testing.T) {
	p := makePool(t)
	waiting := put(t, p, StateWaiting)
	started := make(chan struct{})
	cancelled := make(chan struct{})
	late := new(testSession)
	result := acquireAsync(p, context.Background(), func(ctx context.Context) (*testSession, error) {
		close(started)
		<-ctx.Done()
		close(cancelled)
		late.state.Store(uint32(StateActive))
		return late, nil // A socket completed concurrently with cancellation.
	})
	await(t, started)
	waiting.state.Store(uint32(StateReady))
	p.NotifyReady()
	got := await(t, result)
	if got.err != nil || !got.reused || got.session != waiting {
		t.Fatalf("result = %+v", got)
	}
	await(t, cancelled)
	awaitClosed(t, late)
	if _, found, _ := p.Take(); found {
		t.Fatal("session checked out twice")
	}
	got.session.Close()
}

func TestAcquireFreshWinsWithoutWaitingForPool(t *testing.T) {
	p := makePool(t)
	put(t, p, StateWaiting)
	want := new(testSession)
	want.state.Store(uint32(StateActive))
	got, reused, err := p.Acquire(context.Background(), func(context.Context) (*testSession, error) { return want, nil })
	if err != nil || reused || got != want {
		t.Fatalf("result = %v, %v, %v", got, reused, err)
	}
	if got.closed.Load() != 0 {
		t.Fatal("winning fresh socket was closed")
	}
	got.Close()
}

func TestAcquireNotifiedWhenDrainFinishesBeforePoolInsertion(t *testing.T) {
	p := makePool(t)
	started := make(chan struct{})
	result := acquireAsync(p, context.Background(), func(ctx context.Context) (*testSession, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	await(t, started)
	ready := new(testSession)
	ready.state.Store(uint32(StateReady))
	p.NotifyReady() // The read finished before Close inserted the session.
	p.MoveToPool(ready, StateWaiting, false)
	got := await(t, result)
	if got.err != nil || !got.reused || got.session != ready {
		t.Fatalf("result = %+v", got)
	}
	got.session.Close()
}

func TestAcquireReadyCanRescueDialFailure(t *testing.T) {
	p := makePool(t)
	ready := new(testSession)
	ready.state.Store(uint32(StateReady))
	got, reused, err := p.Acquire(context.Background(), func(context.Context) (*testSession, error) {
		p.MoveToPool(ready, StateReady, false)
		return nil, errors.New("dial failed")
	})
	if err != nil || !reused || got != ready {
		t.Fatalf("result = %v, %v, %v", got, reused, err)
	}
	got.Close()
}

func TestAcquireDialFailureWithoutReadySession(t *testing.T) {
	p := makePool(t)
	want := errors.New("unreachable")
	got, reused, err := p.Acquire(context.Background(), func(context.Context) (*testSession, error) { return nil, want })
	if !errors.Is(err, want) || reused || got != nil {
		t.Fatalf("result = %v, %v, %v", got, reused, err)
	}
}

func TestAcquireCancellationOwnsLateSuccess(t *testing.T) {
	p := makePool(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	late := new(testSession)
	result := acquireAsync(p, ctx, func(ctx context.Context) (*testSession, error) {
		close(started)
		<-ctx.Done()
		return late, nil
	})
	await(t, started)
	cancel()
	got := await(t, result)
	if !errors.Is(got.err, context.Canceled) || got.session != nil {
		t.Fatalf("result = %+v", got)
	}
	awaitClosed(t, late)
}

func TestAcquirePoolClosureWakesDemand(t *testing.T) {
	p := makePool(t)
	started := make(chan struct{})
	cancelled := make(chan struct{})
	result := acquireAsync(p, context.Background(), func(ctx context.Context) (*testSession, error) {
		close(started)
		<-ctx.Done()
		close(cancelled)
		return nil, ctx.Err()
	})
	await(t, started)
	p.Close()
	got := await(t, result)
	if !errors.Is(got.err, net.ErrClosed) || got.session != nil {
		t.Fatalf("result = %+v", got)
	}
	await(t, cancelled)
}

func TestAcquireConcurrentWaitersDoNotShareSession(t *testing.T) {
	p := makePool(t)
	const count = 8
	started := make(chan struct{}, count)
	finishDial := make(chan struct{})
	var cancellations atomic.Int32
	results := make([]<-chan acquisition, count)
	for i := range results {
		results[i] = acquireAsync(p, context.Background(), func(ctx context.Context) (*testSession, error) {
			started <- struct{}{}
			select {
			case <-ctx.Done():
				cancellations.Add(1)
				return nil, ctx.Err()
			case <-finishDial:
				s := new(testSession)
				s.state.Store(uint32(StateActive))
				return s, nil
			}
		})
	}
	for range count {
		await(t, started)
	}
	pooled := put(t, p, StateReady)
	// Let the pooled winner cancel before allowing the other demand dials.
	deadline := time.Now().Add(3 * time.Second)
	for cancellations.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	close(finishDial)
	seen := make(map[*testSession]bool)
	var reused int
	for _, result := range results {
		got := await(t, result)
		if got.err != nil || got.session == nil {
			t.Fatalf("result = %+v", got)
		}
		if seen[got.session] {
			t.Fatal("two acquisitions own the same socket")
		}
		seen[got.session] = true
		if got.reused {
			reused++
			if got.session != pooled {
				t.Fatal("unexpected pooled winner")
			}
		}
		got.session.Close()
	}
	if reused != 1 || cancellations.Load() != 1 {
		t.Fatalf("reused=%d, cancellations=%d", reused, cancellations.Load())
	}
}

func TestAcquireResetDoesNotWaitForRemovedSession(t *testing.T) {
	p := makePool(t)
	waiting := put(t, p, StateWaiting)
	started := make(chan struct{})
	finishDial := make(chan struct{})
	fresh := new(testSession)
	result := acquireAsync(p, context.Background(), func(context.Context) (*testSession, error) {
		close(started)
		<-finishDial
		return fresh, nil
	})
	await(t, started)
	p.Reset()
	close(finishDial)
	got := await(t, result)
	if got.err != nil || got.reused || got.session != fresh || waiting.closed.Load() != 1 {
		t.Fatalf("result = %+v", got)
	}
	got.session.Close()
}
