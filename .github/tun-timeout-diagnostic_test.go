//go:build linux && !android

package tun

import (
	"bytes"
	"fmt"
	"io"
	"slices"
	"sync"
	"testing"
	"time"
)

func TestDiagnosticSACKReneging(t *testing.T) {
	for _, mode := range []string{"natural", "early-recovery", "gate-sacks"} {
		t.Run(mode, func(modeTest *testing.T) {
			for _, ipv6 := range []bool{false, true} {
				modeTest.Run(fmt.Sprintf("ipv6=%v", ipv6), func(test *testing.T) {
					test.Parallel()
					var traceAccess sync.Mutex
					var trace []string
					checkpoint := func(phase string, conn *GoConn) {
						if conn == nil {
							return
						}
						// Congestion hooks run on the owning engine. Copy its state
						// here rather than reading non-atomic fields from the test.
						state := fmt.Sprintf("phase=%s state=%d cwnd=%d ssthresh=%d flight=%+v peerWindow=%d unacked=%d sent=%d buffered=%d permit=%d packetPermit=%d", phase, conn.congestionState, conn.congestionWindow, conn.slowStartThreshold, conn.flight, conn.peerWindow, conn.sendUnacked.Load(), conn.sentTail.Load(), conn.bufferedTail.Load(), conn.sendPermit.Load(), conn.sendPacketPermit.Load())
						traceAccess.Lock()
						if len(trace) == 0 || trace[len(trace)-1] != state {
							if len(trace) == 48 {
								trace = trace[1:]
							}
							trace = append(trace, state)
						}
						traceAccess.Unlock()
					}
					test.Cleanup(func() {
						if test.Failed() {
							traceAccess.Lock()
							defer traceAccess.Unlock()
							for _, state := range trace {
								test.Log(state)
							}
						}
					})
					fixture, traffic := newKernelTCPFixture(test, kernelStackConfig{mtu: 1500}, kernelTCPConfig{checkpoint: checkpoint})
					client, server := fixture.pair(test, ipv6)
					mss := int(server.effectiveMSS.Load())
					payload := kernelPayload(8*mss, 137)
					barrier := newKernelTCPBarrier(test)
					paused := false
					initialSent := false
					traffic.setFilter(server, func(event kernelTCPEvent) kernelTCPAction {
						if event.outgoing && event.end >= uint64(len(payload)+1) {
							initialSent = true
						}
						if event.outgoing && event.sequence == 1 && event.end > event.sequence {
							return kernelTCPAction{drop: true}
						}
						if mode == "early-recovery" && !paused && event.outgoing && event.sequence == uint64(3*mss+1) {
							paused = true
							return kernelTCPAction{pause: barrier}
						}
						return kernelTCPAction{drop: mode == "gate-sacks" && !initialSent && !event.outgoing && len(event.sacks) > 0}
					})
					written := make(chan error, 1)
					go func() {
						_, err := server.Write(payload)
						written <- err
					}()
					if mode == "early-recovery" {
						select {
						case <-barrier.entered:
						case <-time.After(kernelTCPTimeout):
							test.Fatal("fourth packet did not reach the controlled pause")
						}
						traffic.await(test, server, "first packet retransmission before resuming the fourth", func(flow kernelTCPFlow) bool {
							attempts := 0
							for _, event := range flow.events {
								if event.outgoing && event.sequence == 1 && event.length > 0 {
									attempts++
								}
							}
							return attempts >= 2
						})
						barrier.once.Do(func() { close(barrier.resume) })
					}
					if err := kernelTCPResult(test, written, "write initial payload"); err != nil {
						test.Fatal(err)
					}
					retained := goSackBlock{start: uint64(mss + 1), end: uint64(len(payload) + 1)}
					traffic.await(test, server, "kernel SACK of queued out-of-order data", func(flow kernelTCPFlow) bool {
						return slices.ContainsFunc(flow.events, func(event kernelTCPEvent) bool {
							return !event.outgoing && slices.Contains(event.sacks, retained)
						})
					})
					if err := client.SetReadBuffer(512); err != nil {
						test.Fatal(err)
					}
					traffic.setFilter(server, nil)
					traffic.await(test, server, "kernel reneging on its SACK interval", func(flow kernelTCPFlow) bool {
						return slices.ContainsFunc(flow.events, func(event kernelTCPEvent) bool {
							return !event.outgoing && event.ack >= retained.start && event.ack < retained.end
						})
					})
					if err := client.SetReadBuffer(64 << 10); err != nil {
						test.Fatal(err)
					}
					client.SetReadDeadline(time.Now().Add(4 * time.Second))
					data := make([]byte, len(payload))
					n, err := io.ReadFull(client, data)
					if err != nil || !bytes.Equal(data, payload) {
						test.Fatalf("SACK reneging: received=%d/%d: %v", n, len(payload), err)
					}
					if err := server.CloseWrite(); err != nil {
						test.Fatal(err)
					}
					if _, err := client.Read(data[:1]); err != io.EOF {
						test.Fatalf("stream end after SACK reneging: %v", err)
					}
				})
			}
		})
	}
}
