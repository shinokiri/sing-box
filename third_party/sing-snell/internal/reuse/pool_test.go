package reuse

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testSession struct {
	state  atomic.Uint32
	closed atomic.Int32
	inUse  atomic.Int32
}

func (s *testSession) ReuseState() *atomic.Uint32 { return &s.state }
func (s *testSession) Close() error {
	s.state.Store(uint32(StateClosed))
	s.closed.Add(1)
	return nil
}

func makePool(t *testing.T) *Pool[*testSession] {
	t.Helper()
	p := new(Pool[*testSession])
	p.Init()
	t.Cleanup(func() { p.Close() })
	return p
}

func put(t *testing.T, p *Pool[*testSession], state State) *testSession {
	t.Helper()
	s := new(testSession)
	s.state.Store(uint32(state))
	if !p.MoveToPool(s, state, false) {
		t.Fatal("session rejected")
	}
	return s
}

func TestPoolRetainsRecentlyUsedSession(t *testing.T) {
	p := makePool(t)
	put(t, p, StateReady)
	recent := put(t, p, StateReady)
	put(t, p, StateWaiting)
	for i := 0; i < 3; i++ {
		got, found, closed := p.Take()
		if !found || closed || got != recent {
			t.Fatal("recent usable session was not retained across sequential requests")
		}
		got.state.Store(uint32(StateReady))
		if !p.MoveToPool(got, StateReady, false) {
			t.Fatal("return rejected")
		}
	}
}

func TestPoolSelectionStillExpiresOlderEntries(t *testing.T) {
	p := makePool(t)
	old := put(t, p, StateReady)
	p.entries.Front().Value.time = time.Now().Add(-PoolMaxAge - time.Second)
	recent := put(t, p, StateReady)
	got, found, closed := p.Take()
	if !found || closed || got != recent {
		t.Fatal("eligible session not selected")
	}
	if old.closed.Load() != 1 {
		t.Fatal("older expired entry was not closed")
	}
	if p.entries.Len() != 0 {
		t.Fatal("expired entry retained")
	}
	got.Close()
}

func TestPoolSkipsWaitingAndClosedEntries(t *testing.T) {
	p := makePool(t)
	ready := put(t, p, StateReady)
	put(t, p, StateWaiting)
	put(t, p, StateClosed)
	got, found, closed := p.Take()
	if !found || closed || got != ready {
		t.Fatal("unusable entry selected")
	}
	got.Close()
	if _, found, closed := p.Take(); found || closed {
		t.Fatal("waiting entry was reused")
	}
}

func TestPoolCapacityResetAndClosure(t *testing.T) {
	p := makePool(t)
	var sessions []*testSession
	for i := 0; i < PoolSize; i++ {
		sessions = append(sessions, put(t, p, StateReady))
	}
	extra := new(testSession)
	if p.MoveToPool(extra, StateReady, false) || extra.closed.Load() != 1 {
		t.Fatal("capacity exceeded")
	}
	p.Reset()
	for _, s := range sessions {
		if s.closed.Load() != 1 {
			t.Fatal("reset leaked idle session")
		}
	}
	if _, found, closed := p.Take(); found || closed {
		t.Fatal("reset closed pool or retained sessions")
	}
	p.Close()
	if _, found, closed := p.Take(); found || !closed {
		t.Fatal("closed pool accepted checkout")
	}
	late := new(testSession)
	if p.MoveToPool(late, StateReady, false) || late.closed.Load() != 1 {
		t.Fatal("late return leaked")
	}
}

func TestPoolConcurrentCheckoutIsExclusive(t *testing.T) {
	p := makePool(t)
	for i := 0; i < 4; i++ {
		put(t, p, StateReady)
	}
	var wg sync.WaitGroup
	var duplicate atomic.Bool
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				s, found, closed := p.Take()
				if closed {
					duplicate.Store(true)
					return
				}
				if !found {
					continue
				}
				if s.inUse.Add(1) != 1 {
					duplicate.Store(true)
				}
				s.inUse.Add(-1)
				s.state.Store(uint32(StateReady))
				if !p.MoveToPool(s, StateReady, false) {
					duplicate.Store(true)
				}
			}
		}()
	}
	wg.Wait()
	if duplicate.Load() {
		t.Fatal("concurrent checkout or return violated session ownership")
	}
}
