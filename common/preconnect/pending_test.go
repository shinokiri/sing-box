package preconnect

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func preparing(t *testing.T, d *Dialer, f *fixture) request {
	t.Helper()
	first := demand(d)
	reply(t, next(t, f))
	received(t, first).Close()
	return next(t, f)
}

func cancelled(t *testing.T, ctx context.Context) {
	t.Helper()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("losing dial was not cancelled")
	}
}

func TestPendingPreparationCanServeCurrentDemand(t *testing.T) {
	d, f := newFixture(t)
	background := preparing(t, d, f)
	second := demand(d)
	foreground := next(t, f)
	want, peer := reply(t, background)
	got := received(t, second)
	if got != want {
		t.Fatal("request ignored preparation finishing during demand")
	}
	cancelled(t, foreground.ctx)
	go func() { peer.Write([]byte("ok")) }()
	var b [2]byte
	if _, err := io.ReadFull(got, b[:]); err != nil || string(b[:]) != "ok" {
		t.Fatalf("handoff read: %q %v", b, err)
	}
	got.Close()
	next(t, f) // At most one replacement is prepared after this real demand.
	if len(f.requests) != 0 {
		t.Fatal("prepared more than one replacement")
	}
}

func TestForegroundDoesNotWaitForStalledPreparation(t *testing.T) {
	d, f := newFixture(t)
	background := preparing(t, d, f)
	second := demand(d)
	foreground := next(t, f)
	want, _ := reply(t, foreground)
	if received(t, second) != want {
		t.Fatal("foreground winner was not returned")
	}
	if background.ctx.Err() != nil {
		t.Fatal("background preparation was unnecessarily cancelled")
	}
	want.Close()
	ready, _ := reply(t, background)
	waitSpare(t, d)
	if received(t, demand(d)) != ready {
		t.Fatal("background result was lost after foreground success")
	}
}

func TestResetRetiresPreparationWithoutFailingActualDemand(t *testing.T) {
	d, f := newFixture(t)
	background := preparing(t, d, f)
	result := demand(d)
	foreground := next(t, f)
	d.Reset()
	cancelled(t, background.ctx)
	want, _ := reply(t, foreground)
	if received(t, result) != want {
		t.Fatal("retiring speculation failed a real demand")
	}
	want.Close()
}

type callbackDialer struct {
	N.Dialer
	dial func(context.Context, string, M.Socksaddr) (net.Conn, error)
}

func (d *callbackDialer) DialContext(ctx context.Context, n string, a M.Socksaddr) (net.Conn, error) {
	return d.dial(ctx, n, a)
}

func thirdCallback(t *testing.T, dial func(context.Context) (net.Conn, error)) (*Dialer, *fixture) {
	t.Helper()
	f := &fixture{requests: make(chan request, 100)}
	var calls atomic.Int32
	underlying := &callbackDialer{dial: func(ctx context.Context, network string, address M.Socksaddr) (net.Conn, error) {
		if calls.Add(1) == 3 {
			return dial(ctx)
		}
		return f.DialContext(ctx, network, address)
	}}
	d := New(context.Background(), underlying, testServer)
	t.Cleanup(func() { d.Close() })
	return d, f
}

func TestPendingFailureDoesNotFailHealthyDemand(t *testing.T) {
	foregroundStarted := make(chan struct{})
	finish := make(chan struct{})
	want, peer := net.Pipe()
	defer peer.Close()
	d, f := thirdCallback(t, func(ctx context.Context) (net.Conn, error) {
		close(foregroundStarted)
		select {
		case <-finish:
			return want, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	background := preparing(t, d, f)
	second := demand(d)
	<-foregroundStarted
	// The real background caller fails its own dial without resetting the node.
	d.access.Lock()
	cancel := d.cancel
	d.access.Unlock()
	cancel()
	cancelled(t, background.ctx)
	close(finish)
	if received(t, second) != want {
		t.Fatal("failed background dial cancelled a healthy foreground")
	}
	d.Close()
	want.Close()
}

func TestLateForegroundSuccessAfterPendingWinnerIsClosed(t *testing.T) {
	late, peer := net.Pipe()
	defer peer.Close()
	started := make(chan struct{})
	// A late callback deliberately returns a successful socket concurrently
	// with cancellation.
	d, f := thirdCallback(t, func(ctx context.Context) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		return late, nil
	})
	background := preparing(t, d, f)
	second := demand(d)
	<-started
	want, _ := reply(t, background)
	if received(t, second) != want {
		t.Fatal("preparation did not win")
	}
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("late socket leaked: %v", err)
	}
	want.Close()
}

func TestConcurrentRequestsDoNotSharePendingSpare(t *testing.T) {
	d, f := newFixture(t)
	background := preparing(t, d, f)
	const count = 8
	results := make(chan net.Conn, count)
	for range count {
		go func() { results <- <-demand(d) }()
	}
	foreground := make([]request, count)
	for i := range foreground {
		foreground[i] = next(t, f)
	}
	want, _ := reply(t, background)
	if received(t, results) != want {
		t.Fatal("pending spare did not serve one request")
	}
	seen := map[net.Conn]bool{want: true}
	want.Close()
	var cancelledCount int
	for _, request := range foreground {
		if request.ctx.Err() != nil {
			cancelledCount++
			continue
		}
		reply(t, request)
	}
	if cancelledCount != 1 {
		t.Fatalf("cancelled %d real dials, want one", cancelledCount)
	}
	for range count - 1 {
		got := received(t, results)
		if seen[got] {
			t.Fatal("multiple requests own one connection")
		}
		seen[got] = true
		got.Close()
	}
}
