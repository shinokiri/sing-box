package daemon

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type testProgressManager struct {
	adapter.OutboundManager
	items []adapter.Outbound
}

func (m testProgressManager) Outbounds() []adapter.Outbound { return m.items }

func (m testProgressManager) Outbound(tag string) (adapter.Outbound, bool) {
	for _, item := range m.items {
		if item.Tag() == tag {
			return item, true
		}
	}
	return nil, false
}

type testProgressGroup struct {
	adapter.OutboundGroup
	items []adapter.Outbound
}

func (g testProgressGroup) Tag() string                      { return "all" }
func (g testProgressGroup) Type() string                     { return "selector" }
func (g testProgressGroup) Selected(string) adapter.Outbound { return g.items[0] }
func (g testProgressGroup) All() []string {
	var tags []string
	for _, item := range g.items {
		tags = append(tags, item.Tag())
	}
	return tags
}

type testProgressNode struct {
	outbound.Adapter
	started chan struct{}
	release chan struct{}
	calls   atomic.Int32
}

func (n *testProgressNode) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	n.calls.Add(1)
	n.started <- struct{}{}
	select {
	case <-n.release:
		return nil, errors.New("controlled failure")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (n *testProgressNode) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unexpected UDP")
}

func TestURLTestServiceWaitsForWholeRoundAndJoinsRepeatClick(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	history := urltest.NewHistoryStorage()
	newNode := func(tag string) *testProgressNode {
		history.StoreURLTestHistory(tag, &adapter.URLTestHistory{Time: time.Now().Add(-time.Minute), Delay: 123})
		return &testProgressNode{Adapter: outbound.NewAdapter("test", tag, []string{N.NetworkTCP}, nil), started: make(chan struct{}, 2), release: make(chan struct{})}
	}
	a, b := newNode("a"), newNode("b")
	g := testProgressGroup{items: []adapter.Outbound{a, b}}
	m := testProgressManager{items: []adapter.Outbound{g, a, b}}
	s := &StartedService{serviceStatus: &ServiceStatus{Status: ServiceStatus_STARTED}, instance: &Instance{ctx: ctx, urlTestHistoryStorage: history, outboundManager: m, logFactory: log.NewNOPFactory()}}
	// Legacy asynchronous calls still return after the task is registered.
	if _, err := s.URLTest(ctx, &URLTestRequest{OutboundTag: "all"}); err != nil {
		t.Fatal(err)
	}
	for _, node := range []*testProgressNode{a, b} {
		select {
		case <-node.started:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	snapshot := s.readGroups().Group[0]
	if !snapshot.UrlTestRunning || !snapshot.UrlTestProgressSupported {
		t.Fatal("running task absent from subscription snapshot")
	}
	for _, item := range snapshot.Items {
		if item.UrlTestDelay != 0 || item.UrlTestState != urltest.TestRunning {
			t.Fatal("pending snapshot exposed an old delay")
		}
		if history.LoadURLTestHistory(item.Tag).Delay != 123 {
			t.Fatal("presentation change erased routing history")
		}
	}
	waiting := make(chan error, 1)
	go func() { _, err := s.URLTest(ctx, &URLTestRequest{OutboundTag: "all", Wait: true}); waiting <- err }()
	select {
	case err := <-waiting:
		t.Fatalf("request returned before completion: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(a.release)
	for history.LoadTestStatus("a").State != urltest.TestFailed {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(time.Millisecond):
		}
	}
	partial := s.readGroups().Group[0]
	if !partial.UrlTestRunning || partial.Items[0].UrlTestState != urltest.TestFailed || !history.LoadTestStatus("b").Pending() {
		t.Fatal("partial completion was presented as a finished round")
	}
	close(b.release)
	select {
	case err := <-waiting:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	finished := s.readGroups().Group[0]
	if finished.UrlTestRunning || a.calls.Load() != 1 || b.calls.Load() != 1 {
		t.Fatal("round did not finish once, or duplicate request launched more tests")
	}
	for _, item := range finished.Items {
		if item.UrlTestState != urltest.TestFailed || item.UrlTestDelay != 0 {
			t.Fatal("final snapshot retained a successful delay")
		}
	}
}
