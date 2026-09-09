package tun

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/checksum"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/logger"
	"github.com/stretchr/testify/require"
)

type udpHistoryPort struct {
	Port
	back ReturnWithUDPMapping
}

func (*udpHistoryPort) PortAddresses() (netip.Addr, netip.Addr) {
	return netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("fd01::1")
}
func (*udpHistoryPort) PortMTU() uint32                           { return 0 }
func (*udpHistoryPort) EndpointIndependentUDP() bool              { return true }
func (*udpHistoryPort) PortSelectorRange() (uint16, uint16)       { return 1, 65535 }
func (*udpHistoryPort) WriteUDPFlowPackets([]UDPFlowPacket) error { return nil }
func (*udpHistoryPort) DetachReturn(Return) error                 { return nil }
func (*udpHistoryPort) WritePackets([][]byte) error               { return nil }
func (p *udpHistoryPort) AttachReturn(r Return) error {
	p.back = r.(ReturnWithUDPMapping)
	return nil
}

type udpHistoryWriteback struct{}

func (udpHistoryWriteback) ReturnHeadroom() int               { return 0 }
func (udpHistoryWriteback) WriteReturnPackets([][]byte) error { return nil }

type udpHistoryHandler struct {
	Handler
	port     Port
	lifetime context.Context
}

func (h udpHistoryHandler) JudgeFlow(_ uint8, _, dest netip.AddrPort, _ []byte) FlowVerdict {
	v := FlowVerdict{Action: ActionFlow, Port: h.port, UDPTimeout: time.Second}
	if dest.Addr() == netip.MustParseAddr("203.0.113.1") {
		v.UDPTimeout = time.Hour
		if h.lifetime != nil {
			v.RouteContexts = []context.Context{h.lifetime}
		}
	}
	return v
}

func udpHistoryPacket(src, dest netip.AddrPort) []byte {
	ip := header.IPv4(make([]byte, 29))
	ip.Encode(&header.IPv4Fields{TotalLength: uint16(len(ip)), TTL: 64, Protocol: uint8(header.UDPProtocolNumber), SrcAddr: src.Addr(), DstAddr: dest.Addr()})
	u := header.UDP(ip.Payload())
	u.Encode(&header.UDPFields{SrcPort: src.Port(), DstPort: dest.Port(), Length: 9})
	u.Payload()[0] = 42
	u.SetChecksum(^checksum.Checksum(u.Payload(), u.CalculateChecksum(header.PseudoHeaderChecksum(header.UDPProtocolNumber, ip.SourceAddressSlice(), ip.DestinationAddressSlice(), u.Length()))))
	ip.SetChecksum(^ip.CalculateChecksum())
	return ip
}

func newUDPHistoryMapping(t testing.TB, retired int, lifetime context.Context) (*ForwardDispatcher, *udpMapping) {
	t.Helper()
	p := new(udpHistoryPort)
	d := NewForwardDispatcher(udpHistoryHandler{port: p, lifetime: lifetime}, udpHistoryWriteback{}, logger.NOP(), time.Minute, time.Minute)
	t.Cleanup(d.Close)
	client := netip.MustParseAddrPort("10.0.0.2:50000")
	d.Dispatch(udpHistoryPacket(client, netip.MustParseAddrPort("203.0.113.1:443")))
	d.Flush()
	// Exercise actual insert/delete paths in batches below the sweep budget.
	// Only the long-lived anchor survives each batch. The mock port has no
	// workers, so advancing the dispatcher's clock here needs no synchronization.
	for i := 0; i < retired; i++ {
		dest := netip.AddrFrom4([4]byte{198, 19, byte(i >> 8), byte(i)})
		d.Dispatch(udpHistoryPacket(client, netip.AddrPortFrom(dest, 443)))
		d.Flush()
		if (i+1)%1000 == 0 || i == retired-1 {
			d.epoch = d.epoch.Add(-31 * time.Second)
			d.Flush()
		}
	}
	m := p.back.UDPMapping(netip.MustParseAddrPort("127.0.0.1:50000")).(*udpMapping)
	require.Len(t, d.table, 1)
	require.Len(t, m.peers, retired+1)
	return d, m
}

func TestUDPMappingHistoryKeepsLiveReplyOwnership(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d, m := newUDPHistoryMapping(t, 4096, ctx)
	unknown := netip.MustParseAddrPort("203.0.113.254:40000")
	reply := func(peer netip.AddrPort) bool {
		return m.ReturnPacket(udpHistoryPacket(peer, m.source))
	}
	require.True(t, m.IsActive())
	require.True(t, reply(unknown))
	require.False(t, reply(netip.MustParseAddrPort("198.19.0.1:40000")), "retired aliases must stay reserved")
	cancel()
	require.False(t, m.IsActive(), "an installed but canceled route is not a live owner")
	require.False(t, reply(unknown))
	// A new route can use the same association while the canceled tuple awaits
	// sweeping. It must become a live owner without reviving the retired peers.
	d.Dispatch(udpHistoryPacket(netip.MustParseAddrPort("10.0.0.2:50000"), netip.MustParseAddrPort("203.0.113.2:443")))
	d.Flush()
	require.True(t, m.IsActive())
	require.True(t, reply(unknown))
	require.False(t, reply(netip.MustParseAddrPort("198.19.0.1:40000")))
	d.ResetNetwork()
	require.False(t, m.IsActive())
	require.ErrorIs(t, m.Context().Err(), context.Canceled)
}

// Each case retains one installed tuple. Increasing only the retired peer
// history must not increase the cost of unknown-peer replies or idle sweeping.
func BenchmarkUDPMappingHistory(b *testing.B) {
	for _, retired := range []int{0, 4096, 16383} {
		for _, operation := range []string{"reply", "active"} {
			b.Run(fmt.Sprintf("retired=%d/%s", retired, operation), func(b *testing.B) {
				_, m := newUDPHistoryMapping(b, retired, nil)
				template := udpHistoryPacket(netip.MustParseAddrPort("203.0.113.254:40000"), m.source)
				raw := make([]byte, len(template))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if operation == "reply" {
						copy(raw, template)
						if !m.ReturnPacket(raw) {
							b.Fatal("live socket rejected unknown peer")
						}
					} else if !m.IsActive() {
						b.Fatal("live socket became inactive")
					}
				}
			})
		}
	}
}
