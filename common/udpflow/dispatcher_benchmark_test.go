package udpflow

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type benchmarkFlowHandler struct {
	tun.Handler
	port     tun.Port
	blocked  chan struct{}
	lifetime context.Context
}

func (h *benchmarkFlowHandler) JudgeFlowContext(ctx context.Context, _ uint8, source, _ netip.AddrPort, _ []byte) tun.FlowVerdict {
	if source.Port() != 50000 {
		h.blocked <- struct{}{}
		<-ctx.Done()
		return tun.FlowVerdict{Action: tun.ActionDrop}
	}
	verdict := tun.FlowVerdict{Action: tun.ActionFlow, Port: h.port}
	if h.lifetime != nil {
		verdict.RouteContexts = []context.Context{h.lifetime}
	}
	return verdict
}

// One packet per iteration, from dispatcher parsing/routing/NAT through the
// real Port queue to PacketConn.WritePacket completion. Includes the input
// copy needed because NAT rewrites packets in place. Framing reserves 128/16
// bytes; DNS, encryption, actual sockets and a TUN device are not simulated.
//
// new_tuple exercises first-packet routing with a warm outbound association.
// Reset every 1024 tuples bounds table size independently of b.N; its amortized
// cost is included in ns/op. Latency samples cover only packet delivery.
// blocked_routes measures the established path with 32 unresolved other tuples.
// selected_group also checks a shared outbound-group lifetime on the warm path.
func BenchmarkDispatcherForward(b *testing.B) {
	for _, ipv6 := range []bool{false, true} {
		for _, size := range []int{64, 1200} {
			for _, mode := range []string{"established", "selected_group", "new_tuple", "blocked_routes"} {
				b.Run(fmt.Sprintf("IPv6=%t/payload=%d/%s", ipv6, size, mode), func(b *testing.B) {
					conn := &benchmarkPacketConn{testPacketConn: newTestPacketConn(16), frontHeadroom: 128, written: make(chan struct{}, 1)}
					port, err := New(Options{DialPacketConn: func(context.Context, M.Socksaddr) (N.NetPacketConn, error) { return conn, nil }})
					if err != nil {
						b.Fatal(err)
					}
					defer port.Close()
					h := &benchmarkFlowHandler{port: port, blocked: make(chan struct{}, 32)}
					if mode == "selected_group" {
						var cancel context.CancelFunc
						h.lifetime, cancel = context.WithCancel(context.Background())
						defer cancel()
					}
					d := tun.NewForwardDispatcher(h, newTestWriteback(), logger.NOP(), time.Minute, time.Minute)
					d.EnableAsyncFlow(context.Background(), func([]byte) { panic("unexpected ordinary fallback") })
					defer d.Close()
					source, destination := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("203.0.113.1")
					if ipv6 {
						source, destination = netip.MustParseAddr("fd00::1"), netip.MustParseAddr("2001:db8::1")
					}
					count := 1
					if mode == "new_tuple" {
						count = 1024
					}
					templates := make([][]byte, count)
					for i := range templates {
						templates[i] = buildTestUDPPacket(b, source, 50000, destination, uint16(10000+i), make([]byte, size))
					}
					d.Dispatch(buildTestUDPPacket(b, source, 50000, destination, 443, make([]byte, size)))
					d.Flush()
					<-conn.written // Warm the outbound association.
					if mode == "blocked_routes" {
						for i := range cap(h.blocked) {
							d.Dispatch(buildTestUDPPacket(b, source, uint16(50001+i), destination, 443, nil))
							<-h.blocked
						}
					}
					raw := make([]byte, len(templates[0]))
					if mode != "new_tuple" {
						copy(raw, templates[0])
						d.Dispatch(raw)
						d.Flush()
						<-conn.written
					}
					samples := make([]int64, 0, min(b.N, 8192))
					stride := max((b.N+8191)/8192, 1)
					b.SetBytes(int64(size))
					b.ReportAllocs()
					b.ResetTimer()
					for i := range b.N {
						if mode == "new_tuple" && i%count == 0 {
							d.ResetNetwork()
						}
						start := time.Now()
						copy(raw, templates[i%count])
						if !d.Dispatch(raw) {
							b.Fatal("packet bypassed dispatcher")
						}
						d.Flush()
						<-conn.written
						elapsed := time.Since(start).Nanoseconds()
						if i%stride == 0 {
							samples = append(samples, elapsed)
						}
					}
					b.StopTimer()
					slices.Sort(samples)
					b.ReportMetric(float64(samples[(len(samples)-1)*95/100]), "p95-ns")
					b.ReportMetric(float64(samples[(len(samples)-1)*99/100]), "p99-ns")
				})
			}
		}
	}
}
