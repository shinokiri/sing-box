package udpflow

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type benchmarkPacketConn struct {
	*testPacketConn
	frontHeadroom int
	written       chan struct{}
}

func (c *benchmarkPacketConn) FrontHeadroom() int { return c.frontHeadroom }

func (c *benchmarkPacketConn) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	buffer.ExtendHeader(c.frontHeadroom)
	buffer.Extend(c.rearHeadroom)
	buffer.Release()
	c.written <- struct{}{}
	return nil
}

// Include buffer ownership, queueing, worker scheduling, protocol headroom,
// and write completion. Each iteration forwards 32 packets; no encryption or
// network latency is included.
func BenchmarkPortForward(b *testing.B) {
	for _, ipv6 := range []bool{false, true} {
		for _, size := range []int{64, 1200} {
			for _, framed := range []bool{false, true} {
				b.Run(fmt.Sprintf("IPv6=%t/payload=%d/framed=%t", ipv6, size, framed), func(b *testing.B) {
					conn := &benchmarkPacketConn{testPacketConn: newTestPacketConn(0), written: make(chan struct{}, 32)}
					if framed {
						conn.frontHeadroom, conn.rearHeadroom = 128, 16
					}
					port, err := New(Options{DialPacketConn: func(context.Context, M.Socksaddr) (N.NetPacketConn, error) { return conn, nil }})
					if err != nil {
						b.Fatal(err)
					}
					defer port.Close()
					source, destination := netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("203.0.113.1")
					if ipv6 {
						source, destination = netip.MustParseAddr("fd00::1"), netip.MustParseAddr("2001:db8::1")
					}
					packet := buildTestUDPPacket(b, source, 50000, destination, 443, make([]byte, size))
					packets := make([][]byte, cap(conn.written))
					for i := range packets {
						packets[i] = packet
					}
					// Warm up the association before measuring steady-state forwarding.
					if err = port.WritePackets(packets[:1]); err != nil {
						b.Fatal(err)
					}
					<-conn.written
					b.SetBytes(int64(size * len(packets)))
					b.ReportAllocs()
					for b.Loop() {
						if err = port.WritePackets(packets); err != nil {
							b.Fatal(err)
						}
						for range packets {
							<-conn.written
						}
					}
				})
			}
		}
	}
}
