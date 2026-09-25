package urltest

import "context"

// Test states are also exposed by daemon.GroupItem and libbox.OutboundGroupItem.
const (
	TestIdle int32 = iota
	TestQueued
	TestRunning
	TestSucceeded
	TestFailed
	TestCanceled
)

type TestStatus struct {
	ID    int64
	State int32
	Delay uint16
}

func (s TestStatus) Pending() bool {
	return s.State == TestQueued || s.State == TestRunning
}

// TestBatch records presentation state separately from the history used for
// outbound selection. Its lifetime belongs to the service, not the UI client.
type TestBatch struct {
	storage *HistoryStorage
	id      int64
	tag     string
	targets []string
	done    chan struct{}
}

type testBatchKey struct{}

func (s *HistoryStorage) BeginTestBatch(tag string, targets []string) (*TestBatch, bool) {
	s.access.Lock()
	defer s.access.Unlock()
	if existing := s.testBatches[tag]; existing != nil {
		return existing, false
	}
	if s.testBatches == nil {
		s.testBatches = make(map[string]*TestBatch)
		s.testStatus = make(map[string]TestStatus)
	}
	s.testSequence++
	b := &TestBatch{s, s.testSequence, tag, targets, make(chan struct{})}
	s.testBatches[tag] = b
	for _, target := range targets {
		s.testStatus[target] = TestStatus{ID: b.id, State: TestQueued}
	}
	s.notifyUpdated()
	return b, true
}

func (s *HistoryStorage) LoadTestStatus(tag string) TestStatus {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.testStatus[tag]
}

func (b *TestBatch) Context(ctx context.Context) context.Context {
	return context.WithValue(ctx, testBatchKey{}, b)
}

func (b *TestBatch) Done() <-chan struct{} {
	return b.done
}

func (b *TestBatch) Complete() {
	s := b.storage
	s.access.Lock()
	defer s.access.Unlock()
	if s.testBatches[b.tag] != b {
		return
	}
	// Any remaining targets did not finish (for example, service cancellation).
	for _, tag := range b.targets {
		state := s.testStatus[tag]
		if state.ID == b.id && state.Pending() {
			state.State = TestCanceled
			s.testStatus[tag] = state
		}
	}
	delete(s.testBatches, b.tag)
	close(b.done)
	s.notifyUpdated()
}

func HasTestBatch(ctx context.Context) bool {
	return ctx.Value(testBatchKey{}) != nil
}

func TestStarted(ctx context.Context, tag string) {
	updateTestStatus(ctx, tag, TestRunning, 0)
}

func TestFinished(ctx context.Context, tag string, delay uint16, err error) {
	state := TestSucceeded
	if err != nil {
		state = TestFailed
		if ctx.Err() != nil {
			state = TestCanceled
		}
	}
	updateTestStatus(ctx, tag, state, delay)
}

func updateTestStatus(ctx context.Context, tag string, state int32, delay uint16) {
	b, _ := ctx.Value(testBatchKey{}).(*TestBatch)
	if b == nil {
		return
	}
	s := b.storage
	s.access.Lock()
	defer s.access.Unlock()
	if current := s.testStatus[tag]; current.ID == b.id && s.testBatches[b.tag] == b {
		s.testStatus[tag] = TestStatus{ID: b.id, State: state, Delay: delay}
		s.notifyUpdated()
	}
}
