package urltest

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

func TestProgressRetainsSelectionHistoryAndJoinsDuplicate(t *testing.T) {
	s := NewHistoryStorage()
	old := &adapter.URLTestHistory{Time: time.Now().Add(-time.Minute), Delay: 80}
	s.StoreURLTestHistory("node", old)
	b, owner := s.BeginTestBatch("group", []string{"group", "node"})
	ctx := b.Context(context.Background())
	if !owner || s.LoadTestStatus("node").State != TestQueued || s.LoadURLTestHistory("node") != old {
		t.Fatal("starting a round must queue its nodes without clearing selection history")
	}
	duplicate, owner := s.BeginTestBatch("group", []string{"group", "node"})
	if owner || duplicate != b {
		t.Fatal("duplicate request did not join the active round")
	}
	TestStarted(ctx, "node")
	// An unrelated background result must not finish the manual round.
	s.StoreURLTestHistory("node", &adapter.URLTestHistory{Time: time.Now(), Delay: 30})
	if s.LoadTestStatus("node").State != TestRunning {
		t.Fatal("background result ended an in-flight manual test")
	}
	s.DeleteURLTestHistory("node")
	TestFinished(ctx, "node", 0, errors.New("unreachable"))
	if s.LoadTestStatus("node").State != TestFailed || s.LoadURLTestHistory("node") != nil {
		t.Fatal("failure did not replace the old result")
	}
	select {
	case <-b.Done():
		t.Fatal("node completion ended the entire round")
	default:
	}
	TestFinished(ctx, "group", 0, nil)
	b.Complete()
	<-duplicate.Done()
	// Later automatic success is still reflected after the manual round.
	s.StoreURLTestHistory("node", &adapter.URLTestHistory{Time: time.Now(), Delay: 25})
	if s.LoadTestStatus("node").State != TestSucceeded {
		t.Fatal("automatic recovery was masked by an earlier manual failure")
	}
}

func TestProgressNewRoundIgnoresLateCallbacksAndCancellation(t *testing.T) {
	s := NewHistoryStorage()
	old, _ := s.BeginTestBatch("first", []string{"first", "shared"})
	next, _ := s.BeginTestBatch("second", []string{"second", "shared"})
	oldCtx := old.Context(context.Background())
	TestStarted(oldCtx, "shared")
	TestFinished(oldCtx, "shared", 100, nil)
	old.Complete()
	if got := s.LoadTestStatus("shared"); got.ID != next.id || got.State != TestQueued {
		t.Fatalf("older task overwrote the new round: %+v", got)
	}
	next.Complete()
	if s.LoadTestStatus("shared").State != TestCanceled {
		t.Fatal("unfinished targets must leave pending state on cancellation")
	}
	newRound, owner := s.BeginTestBatch("second", []string{"second", "shared"})
	if !owner || newRound.id <= next.id {
		t.Fatal("completed round was not replaced with a new identity")
	}
	newRound.Complete()
}

func TestProgressConcurrentSnapshots(t *testing.T) {
	s := NewHistoryStorage()
	b, _ := s.BeginTestBatch("node", []string{"node"})
	ctx := b.Context(context.Background())
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Go(func() {
			for n := 0; n < 100; n++ {
				TestStarted(ctx, "node")
				s.LoadTestStatus("node")
				TestFinished(ctx, "node", 20, nil)
			}
		})
	}
	wg.Wait()
	b.Complete()
}
