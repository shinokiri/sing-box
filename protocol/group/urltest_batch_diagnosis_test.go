package group

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Diagnostic characterization of the released batch implementation. This
// intentionally records existing behavior; it is not a proposed UI contract.
// Every fixture connection fails, and no public network requests are made.
type batchDiagnosisOutbound struct {
	outbound.Adapter
	started chan<- string
}

func (d *batchDiagnosisOutbound) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	d.started <- d.Tag()
	<-ctx.Done()
	return nil, ctx.Err()
}

func (d *batchDiagnosisOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, fmt.Errorf("unexpected UDP request")
}

func TestURLTestBatchDiagnosisStaleSuccessWhileEveryAttemptFails(t *testing.T) {
	const count = 21
	ctx, cancel := context.WithTimeout(context.Background(), 65*time.Second)
	defer cancel()
	history := urltest.NewHistoryStorage()
	started := make(chan string, count)
	outbounds := make([]adapter.Outbound, 0, count)
	previousTime := time.Now().Add(-time.Minute)
	for i := 0; i < count; i++ {
		tag := fmt.Sprintf("unreachable-%02d", i)
		outbounds = append(outbounds, &batchDiagnosisOutbound{
			Adapter: outbound.NewAdapter("diagnostic", tag, []string{N.NetworkTCP}, nil),
			started: started,
		})
		history.StoreURLTestHistory(tag, &adapter.URLTestHistory{Time: previousTime, Delay: 100})
	}
	begin := time.Now()
	done := make(chan map[string]uint16, 1)
	go func() {
		done <- URLTestOutbounds(ctx, nil, history, log.NewNOPFactory().Logger(), outbounds, "http://probe.invalid/generate_204", 0, true)
	}()
	attempts := 0
	waitStarted := func(want int) {
		t.Helper()
		for attempts < want {
			select {
			case <-started:
				attempts++
			case <-ctx.Done():
				t.Fatalf("waiting for attempt %d: %v", want, ctx.Err())
			}
		}
	}
	oldSuccesses := func() int {
		t.Helper()
		var n int
		for _, d := range outbounds {
			if h := history.LoadURLTestHistory(d.Tag()); h != nil {
				if h.Time != previousTime || h.Delay != 100 {
					t.Fatal("a fixture that never succeeds produced a new success record")
				}
				n++
			}
		}
		return n
	}
	waitHistory := func(phase string, want int) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for oldSuccesses() != want {
			if time.Now().After(deadline) {
				t.Fatalf("%s: retained %d old successes, want %d", phase, oldSuccesses(), want)
			}
			time.Sleep(time.Millisecond)
		}
		t.Logf("phase=%s elapsed=%s started=%d old_successes_displayable=%d actual_successes=0", phase, time.Since(begin).Round(time.Millisecond), attempts, want)
	}

	waitStarted(10)
	waitHistory("first_ten_pending", 21)
	waitStarted(20)
	waitHistory("first_ten_timed_out", 11)
	waitStarted(21)
	waitHistory("first_twenty_timed_out", 1)
	select {
	case results := <-done:
		if len(results) != 0 {
			t.Fatalf("unexpected successful results: %v", results)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	waitHistory("single_batch_finished", 0)
}
