package reuse

import (
	"testing"
	"time"
)

func TestPoolPrefersLargerReceiveThreshold(t *testing.T) {
	p := makePool(t)
	warm := putMeasured(t, p, StateReady, 4<<20)
	putMeasured(t, p, StateReady, 64<<10)
	got, found, closed := p.Take()
	if !found || closed || got != warm {
		t.Fatal("recent small-window session displaced a ready larger-window session")
	}
	got.Close()
}

func TestPoolEqualReceiveThresholdUsesRecency(t *testing.T) {
	p := makePool(t)
	putMeasured(t, p, StateReady, 4<<20)
	recent := putMeasured(t, p, StateReady, 4<<20)
	got, found, _ := p.Take()
	if !found || got != recent {
		t.Fatal("equal receive thresholds did not retain recent-first order")
	}
	got.Close()
}

func TestPoolUnknownRecentThresholdUsesRecency(t *testing.T) {
	p := makePool(t)
	putMeasured(t, p, StateReady, 4<<20)
	recent := put(t, p, StateReady)
	got, found, _ := p.Take()
	if !found || got != recent {
		t.Fatal("unavailable comparison changed recent-first behavior")
	}
	got.Close()
}

func TestPoolCannotUseWaitingLargeWindow(t *testing.T) {
	p := makePool(t)
	putMeasured(t, p, StateWaiting, 4<<20)
	ready := putMeasured(t, p, StateReady, 64<<10)
	got, found, _ := p.Take()
	if !found || got != ready {
		t.Fatal("receive threshold made a draining session eligible")
	}
	got.Close()
}

func TestPoolExpiresLargeWindowDuringSelection(t *testing.T) {
	p := makePool(t)
	warm := putMeasured(t, p, StateReady, 4<<20)
	recent := putMeasured(t, p, StateReady, 64<<10)
	p.entries.Front().Value.time = time.Now().Add(-PoolMaxAge - time.Second)
	got, found, _ := p.Take()
	if !found || got != recent || warm.closed.Load() != 1 {
		t.Fatal("expired large-window connection was retained or selected")
	}
	got.Close()
}

func TestPoolResamplesAfterSelectedSessionCloses(t *testing.T) {
	p := makePool(t)
	closing := putMeasured(t, p, StateReady, 4<<20)
	closing.sampleHook = func() { closing.Close() }
	ready := putMeasured(t, p, StateReady, 64<<10)
	got, found, _ := p.Take()
	if !found || got != ready {
		t.Fatal("close racing with sampling prevented an available checkout")
	}
	got.Close()
}

func TestPoolCapacityRetainsOldLargeWindow(t *testing.T) {
	p := makePool(t)
	warm := putMeasured(t, p, StateReady, 4<<20)
	oldestCold := putMeasured(t, p, StateReady, 64<<10)
	for i := 2; i < PoolSize; i++ {
		putMeasured(t, p, StateReady, 64<<10)
	}
	putMeasured(t, p, StateReady, 2<<20)
	if warm.closed.Load() != 0 || oldestCold.closed.Load() != 1 || p.entries.Len() != PoolSize {
		t.Fatal("capacity replacement evicted a larger receive window")
	}
	got, found, _ := p.Take()
	if !found || got != warm {
		t.Fatal("largest available threshold was not preserved")
	}
	got.Close()
}

func TestPoolFullRejectsSmallerWindow(t *testing.T) {
	p := makePool(t)
	var existing []*testSession
	for i := 0; i < PoolSize; i++ {
		existing = append(existing, putMeasured(t, p, StateReady, 4<<20))
	}
	cold := &testSession{threshold: 64 << 10, measured: true}
	if p.MoveToPool(cold, StateReady, false) || cold.closed.Load() != 1 {
		t.Fatal("small-window return displaced a larger measured window")
	}
	for _, s := range existing {
		if s.closed.Load() != 0 {
			t.Fatal("larger measured window evicted")
		}
	}
}

func TestPoolCapacityFallsBackForUnknownHints(t *testing.T) {
	for _, unknownIncoming := range []bool{false, true} {
		p := makePool(t)
		for i := 0; i < PoolSize; i++ {
			putMeasured(t, p, StateReady, 64<<10)
		}
		if !unknownIncoming {
			p.entries.Front().Value.session.measured = false
		}
		incoming := &testSession{threshold: 4 << 20, measured: !unknownIncoming}
		if p.MoveToPool(incoming, StateReady, false) || incoming.closed.Load() != 1 {
			t.Fatal("full pool guessed a capacity replacement from incomplete hints")
		}
	}
}
