package reuse

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func putMeasured(t *testing.T, p *Pool[*testSession], state State, threshold uint32) *testSession {
	t.Helper()
	s := &testSession{threshold: threshold, measured: true}
	s.state.Store(uint32(state))
	if !p.MoveToPool(s, state, false) {
		t.Fatal("measured return rejected")
	}
	return s
}

func TestPoolFullRetainsLateReturn(t *testing.T) {
	p := makePool(t)
	oldest := putMeasured(t, p, StateReady, 64<<10)
	for i := 1; i < PoolSize; i++ {
		putMeasured(t, p, StateReady, 64<<10)
	}
	recent := &testSession{threshold: 4 << 20, measured: true}
	if !p.MoveToPool(recent, StateReady, false) {
		t.Fatal("recently returned session discarded when idle pool was full")
	}
	if p.entries.Len() != PoolSize || oldest.closed.Load() != 1 || recent.closed.Load() != 0 {
		t.Fatal("full pool did not replace only its oldest entry")
	}
	got, found, closed := p.Take()
	if !found || closed || got != recent {
		t.Fatal("newest returned session was not available for the next request")
	}
	got.Close()
}

func TestPoolClosedReturnDoesNotEvict(t *testing.T) {
	p := makePool(t)
	var existing []*testSession
	for i := 0; i < PoolSize; i++ {
		existing = append(existing, putMeasured(t, p, StateReady, 64<<10))
	}
	dead := new(testSession)
	dead.state.Store(uint32(StateClosed))
	if p.MoveToPool(dead, StateReady, false) {
		t.Fatal("already closed return admitted")
	}
	if p.entries.Len() != PoolSize {
		t.Fatal("closed return changed pool capacity")
	}
	for _, s := range existing {
		if s.closed.Load() != 0 {
			t.Fatal("closed return evicted a usable session")
		}
	}
}

func TestPoolFullDoesNotCloseCheckedOutSession(t *testing.T) {
	p := makePool(t)
	put(t, p, StateReady)
	active, found, _ := p.Take()
	if !found {
		t.Fatal("checkout failed")
	}
	defer active.Close()
	for i := 0; i < PoolSize+1; i++ {
		putMeasured(t, p, StateReady, 64<<10)
	}
	if active.closed.Load() != 0 || State(active.state.Load()) != StateActive {
		t.Fatal("idle replacement interfered with checked-out session")
	}
}

type drainTestSession struct {
	testSession
	done chan struct{}
	once sync.Once
}

func (s *drainTestSession) Close() error {
	s.once.Do(func() {
		s.testSession.Close()
		close(s.done)
	})
	return nil
}

func TestPoolFullEvictionCompletesWaitingDrain(t *testing.T) {
	p := new(Pool[*drainTestSession])
	p.Init()
	t.Cleanup(func() { p.Close() })
	add := func(state State, drain bool) *drainTestSession {
		s := &drainTestSession{done: make(chan struct{})}
		s.threshold, s.measured = 64<<10, true
		s.state.Store(uint32(state))
		if !p.MoveToPool(s, state, drain) {
			t.Fatal("return rejected")
		}
		if drain {
			go func() {
				<-s.done
				// Exercises the lock boundary used by Take/MoveToPool. Close
				// must wake draining readers after releasing the pool mutex.
				p.IsClosed()
				p.DrainDone()
			}()
		}
		return s
	}
	oldest := add(StateWaiting, true)
	for i := 1; i < PoolSize; i++ {
		add(StateReady, false)
	}
	recent := add(StateWaiting, true)
	if oldest.closed.Load() != 1 || recent.closed.Load() != 0 {
		t.Fatal("wrong waiting session evicted")
	}
	complete := make(chan struct{})
	go func() {
		p.Close()
		close(complete)
	}()
	select {
	case <-complete:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not finish after eviction of a draining session")
	}
}

func TestPoolConcurrentFullReturnsStayBounded(t *testing.T) {
	p := makePool(t)
	const workers, returns = 8, 64
	sessions := make([]*testSession, workers*returns)
	var wg sync.WaitGroup
	var violated atomic.Bool
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for n := 0; n < returns; n++ {
				s := &testSession{threshold: 64 << 10, measured: true}
				sessions[worker*returns+n] = s
				if !p.MoveToPool(s, StateReady, false) {
					violated.Store(true)
				}
				p.access.Lock()
				if p.entries.Len() > PoolSize {
					violated.Store(true)
				}
				p.access.Unlock()
			}
		}(worker)
	}
	wg.Wait()
	p.Close()
	if violated.Load() {
		t.Fatal("concurrent idle returns violated the capacity/admission policy")
	}
	for _, s := range sessions {
		if s.closed.Load() != 1 {
			t.Fatal("returned session leaked or was closed twice")
		}
	}
}
