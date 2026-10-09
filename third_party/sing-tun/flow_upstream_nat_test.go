package tun

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/logger"
	"github.com/stretchr/testify/require"
)

// A shared L3 port exercises upstream reservations independently of the
// fork's socket-style PortWithUDPMapping implementation.
type reservedFlowPort struct {
	pendingPort
	returns  []Return
	held     map[netip.AddrPort]bool
	released []netip.AddrPort
	ranges   []SelectorRange
	expand   bool
}

func newReservedFlowPort() *reservedFlowPort {
	return &reservedFlowPort{pendingPort: pendingPort{sent: make(chan []byte, 16)}, held: make(map[netip.AddrPort]bool)}
}

func (p *reservedFlowPort) AttachReturn(r Return) error              { p.returns = append(p.returns, r); return nil }
func (p *reservedFlowPort) PortSelectorRanges(uint8) []SelectorRange { return p.ranges }
func (p *reservedFlowPort) ExpandSelectorRanges(uint8) bool {
	if !p.expand {
		return false
	}
	p.expand = false
	p.ranges = append(p.ranges, SelectorRange{Start: 51000, Count: 1})
	return true
}
func (p *reservedFlowPort) ReserveSelector(_ uint8, a netip.AddrPort) bool {
	if p.held[a] {
		return false
	}
	p.held[a] = true
	return true
}
func (p *reservedFlowPort) ReleaseSelector(_ uint8, a netip.AddrPort) {
	delete(p.held, a)
	p.released = append(p.released, a)
}

func TestForwardSharedNATPreservesReservationsAndReplyOwner(t *testing.T) {
	p := newReservedFlowPort()
	p.ranges = []SelectorRange{{Start: 50000, Count: 8}}
	client := netip.MustParseAddrPort("10.0.0.2:50000")
	peer := netip.MustParseAddrPort("203.0.113.1:443")
	w := []*pendingWriteback{{packets: make(chan []byte, 4)}, {packets: make(chan []byte, 4)}}
	d := make([]*ForwardDispatcher, 2)
	wire := make([]netip.AddrPort, 2)
	for i := range d {
		d[i] = NewForwardDispatcher(udpHistoryHandler{port: p}, w[i], logger.NOP(), time.Minute, time.Minute)
		t.Cleanup(d[i].Close)
		require.True(t, d[i].Dispatch(udpHistoryPacket(client, peer)))
		d[i].Flush()
		parsed, ok := parseForwardPacket(pendingReceive(t, p.sent))
		require.True(t, ok)
		wire[i] = parsed.source
	}
	require.NotEqual(t, wire[0], wire[1], "dispatchers sharing a port must not reserve the same UDP selector")
	for i := range d {
		reply := udpHistoryPacket(peer, wire[i])
		require.Len(t, p.returns[1-i].ReturnPackets([][]byte{reply}), 1, "the other inbound must leave this reply untouched")
		require.Empty(t, p.returns[i].ReturnPackets([][]byte{reply}))
		parsed, ok := parseForwardPacket(pendingReceive(t, w[i].packets))
		require.True(t, ok)
		require.Equal(t, client, parsed.destination)
	}
	d[0].Close()
	require.False(t, p.held[wire[0]])
	require.True(t, p.held[wire[1]], "closing one inbound must retain the other inbound's reservation")
	require.Empty(t, p.returns[1].ReturnPackets([][]byte{udpHistoryPacket(peer, wire[1])}))
	pendingReceive(t, w[1].packets)
	d[1].Close()
	require.Empty(t, p.held)
	require.Len(t, p.released, 2)
}

func TestForwardNATExpandsPastExternallyReservedPort(t *testing.T) {
	p := newReservedFlowPort()
	p.ranges = []SelectorRange{{Start: 50000, Count: 1}}
	p.expand = true
	occupied := netip.MustParseAddrPort("127.0.0.1:50000")
	p.held[occupied] = true
	d := NewForwardDispatcher(udpHistoryHandler{port: p}, udpHistoryWriteback{}, logger.NOP(), time.Minute, time.Minute)
	t.Cleanup(d.Close)
	require.True(t, d.Dispatch(udpHistoryPacket(netip.MustParseAddrPort("10.0.0.2:50000"), netip.MustParseAddrPort("203.0.113.1:443"))))
	d.Flush()
	parsed, ok := parseForwardPacket(pendingReceive(t, p.sent))
	require.True(t, ok)
	require.Equal(t, uint16(51000), parsed.source.Port())
	d.Close()
	require.True(t, p.held[occupied], "externally owned sockets must not be released by the dispatcher")
	require.Equal(t, []netip.AddrPort{parsed.source}, p.released)
}

func TestForwardNATOptionsSurviveWorkerStages(t *testing.T) {
	for _, filtering := range []NATFiltering{NATFilteringEndpointIndependent, NATFilteringAddressDependent, NATFilteringAddressAndPortDependent} {
		t.Run(string(rune('0'+filtering)), func(t *testing.T) {
			p := newReservedFlowPort()
			p.ranges = []SelectorRange{{Start: 50000, Count: 8}}
			w := &pendingWriteback{packets: make(chan []byte, 4)}
			d := NewForwardDispatcherWithOptions(udpHistoryHandler{port: p}, w, logger.NOP(), UDPNatOptions{Timeout: time.Minute, Filtering: filtering}, time.Minute)
			t.Cleanup(d.Close)
			d.NewStage(nil)
			stage := d.NewStage(nil)
			peer := netip.MustParseAddrPort("203.0.113.1:443")
			require.True(t, stage.Dispatch(udpHistoryPacket(netip.MustParseAddrPort("10.0.0.2:50000"), peer)))
			stage.Flush()
			parsed, ok := parseForwardPacket(pendingReceive(t, p.sent))
			require.True(t, ok)
			for _, test := range []struct {
				peer     netip.AddrPort
				accepted bool
			}{
				{netip.MustParseAddrPort("203.0.113.1:444"), filtering != NATFilteringAddressAndPortDependent},
				{netip.MustParseAddrPort("203.0.113.2:444"), filtering == NATFilteringEndpointIndependent},
			} {
				left := p.returns[0].ReturnPackets([][]byte{udpHistoryPacket(test.peer, parsed.source)})
				require.Equal(t, test.accepted, len(left) == 0)
				if test.accepted {
					pendingReceive(t, w.packets)
				}
			}
		})
	}
}

func TestForwardFragmentReplyRespectsRouteRetirement(t *testing.T) {
	p := newReservedFlowPort()
	p.ranges = []SelectorRange{{Start: 50000, Count: 8}}
	w := &pendingWriteback{packets: make(chan []byte, 4)}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	d := NewForwardDispatcher(udpHistoryHandler{port: p, lifetime: ctx}, w, logger.NOP(), time.Minute, time.Minute)
	t.Cleanup(d.Close)
	client := netip.MustParseAddrPort("10.0.0.2:50000")
	peer := netip.MustParseAddrPort("203.0.113.1:443")
	require.True(t, d.Dispatch(udpHistoryPacket(client, peer)))
	d.Flush()
	parsed, ok := parseForwardPacket(pendingReceive(t, p.sent))
	require.True(t, ok)
	fragments, ok := fragmentIPv4Packet(header.IPv4(udpHistoryPacket(peer, parsed.source)), 28)
	require.True(t, ok)
	require.Len(t, fragments, 2)
	require.Empty(t, p.returns[0].ReturnPackets(fragments[:1]))
	first := pendingReceive(t, w.packets)
	require.Equal(t, addrToTCPIP(client.Addr()), header.IPv4(first).DestinationAddress())
	cancel()
	require.Empty(t, p.returns[0].ReturnPackets(fragments[1:]), "retired fragment is consumed without delivery")
	select {
	case <-w.packets:
		t.Fatal("a later fragment revived the canceled route")
	default:
	}
}
