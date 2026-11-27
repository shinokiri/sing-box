package tun

import (
	"context"
	"net/netip"
	"sync"
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
	fragments, ok := fragmentIPv4Packet(header.IPv4(udpHistoryPacket(peer, parsed.source)), 28, 0)
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

type routedTestPort struct {
	*Go
	sent chan []byte
}

func (p *routedTestPort) WritePackets(packets [][]byte) error {
	for _, raw := range packets {
		p.sent <- append([]byte(nil), raw...)
	}
	return nil
}

type paddedReturnWriter struct {
	pendingWriteback
}

func (*paddedReturnWriter) ReturnHeadroom() int { return 12 }

type recordingReturnWriter struct {
	paddedReturnWriter
	batches []int
}

func (w *recordingReturnWriter) WriteReturnPackets(packets [][]byte) error {
	w.batches = append(w.batches, len(packets))
	return w.pendingWriteback.WriteReturnPackets(packets)
}

func newRoutedTestPath(t testing.TB, writer ForwardWriteback, lifetime context.Context) (source, host *ForwardStage, port *routedTestPort) {
	t.Helper()
	router := NewForwardDispatcher(nil, udpHistoryWriteback{}, logger.NOP(), time.Minute, time.Minute)
	t.Cleanup(router.Close)
	host = router.NewStage(nil)
	port = &routedTestPort{
		Go:   &Go{dispatcher: router, inet4Address: netip.MustParseAddr("192.0.2.10"), mtu: 1500},
		sent: make(chan []byte, 4),
	}
	incoming := NewForwardDispatcher(udpHistoryHandler{port: port, lifetime: lifetime}, udpHistoryWriteback{}, logger.NOP(), time.Minute, time.Minute)
	t.Cleanup(incoming.Close)
	incoming.NewStage(nil)
	return incoming.NewStage(writer), host, port
}

func stageRoutedReply(t *testing.T, host *ForwardStage, reply []byte) {
	t.Helper()
	parsed, ok := parseForwardPacket(reply)
	require.True(t, ok)
	require.True(t, host.ReturnParsed(reply, ForwardFrameMeta{}, &parsed))
	clear(reply) // The next RX frame can reuse this storage before Flush.
}

func TestRoutedPortReturnsToOriginatingStage(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	origin := &recordingReturnWriter{paddedReturnWriter: paddedReturnWriter{pendingWriteback{packets: make(chan []byte, 4)}}}
	source, host, port := newRoutedTestPath(t, origin, ctx)
	clients := []netip.AddrPort{netip.MustParseAddrPort("10.0.0.2:50000"), netip.MustParseAddrPort("10.0.0.3:50001")}
	peer := netip.MustParseAddrPort("203.0.113.1:443")
	for _, client := range clients {
		require.True(t, source.Dispatch(udpHistoryPacket(client, peer)))
	}
	source.Flush()
	for _, client := range clients {
		forwarded, ok := parseForwardPacket(pendingReceive(t, port.sent))
		require.True(t, ok)
		require.Equal(t, client, forwarded.source)
		stageRoutedReply(t, host, udpHistoryPacket(peer, client))
	}
	require.Empty(t, origin.batches)
	host.Flush()
	require.Equal(t, []int{2}, origin.batches)
	for _, client := range clients {
		delivered := pendingReceive(t, origin.packets)
		back, ok := parseForwardPacket(delivered[origin.ReturnHeadroom():])
		require.True(t, ok)
		require.Equal(t, client, back.destination)
		require.Equal(t, peer, back.source)
		require.Equal(t, []byte{42}, header.UDP(back.transport).Payload())
	}
	stageRoutedReply(t, host, udpHistoryPacket(peer, clients[0]))
	host.dispatcher.ResetNetwork()
	host.Flush()
	require.Empty(t, origin.packets)

	otherClient := netip.MustParseAddrPort("10.0.0.4:50002")
	otherPeer := netip.MustParseAddrPort("203.0.113.2:443")
	require.True(t, source.Dispatch(udpHistoryPacket(otherClient, otherPeer)))
	source.Flush()
	forwarded, ok := parseForwardPacket(pendingReceive(t, port.sent))
	require.True(t, ok)
	require.Equal(t, otherClient, forwarded.source)
	stageRoutedReply(t, host, udpHistoryPacket(peer, clients[0]))
	stageRoutedReply(t, host, udpHistoryPacket(otherPeer, otherClient))
	cancel()
	host.Flush()
	require.Equal(t, []int{2, 1}, origin.batches)
	remaining, ok := parseForwardPacket(pendingReceive(t, origin.packets)[origin.ReturnHeadroom():])
	require.True(t, ok)
	require.Equal(t, otherPeer, remaining.source)
	require.Equal(t, otherClient, remaining.destination)
	stageRoutedReply(t, host, udpHistoryPacket(peer, clients[1]))
	host.Flush()
	require.Empty(t, origin.packets)

	// Reusing a tuple on the new network cannot revive an old queued reply.
	stageRoutedReply(t, host, udpHistoryPacket(otherPeer, otherClient))
	source.dispatcher.ResetNetwork()
	require.True(t, source.Dispatch(udpHistoryPacket(otherClient, otherPeer)))
	source.Flush()
	forwarded, ok = parseForwardPacket(pendingReceive(t, port.sent))
	require.True(t, ok)
	require.Equal(t, otherClient, forwarded.source)
	stageRoutedReply(t, host, udpHistoryPacket(otherPeer, otherClient))
	host.Flush()
	require.Equal(t, []int{2, 1, 1}, origin.batches)
	pendingReceive(t, origin.packets)
	require.Empty(t, origin.packets)

	source.dispatcher.Close()
	reply := udpHistoryPacket(peer, clients[0])
	parsed, ok := parseForwardPacket(reply)
	require.True(t, ok)
	require.False(t, host.ReturnParsed(reply, ForwardFrameMeta{}, &parsed))
}

func TestRoutedReturnWriteDoesNotLockDispatcher(t *testing.T) {
	origin := &gatedWriteback{pendingWriteback: pendingWriteback{packets: make(chan []byte, 4)}, entered: make(chan struct{}), resume: make(chan struct{})}
	release := sync.OnceFunc(func() { close(origin.resume) })
	source, host, port := newRoutedTestPath(t, origin, nil)
	defer release()
	client, peer := netip.MustParseAddrPort("10.0.0.2:50000"), netip.MustParseAddrPort("203.0.113.1:443")
	require.True(t, source.Dispatch(udpHistoryPacket(client, peer)))
	source.Flush()
	pendingReceive(t, port.sent)
	stageRoutedReply(t, host, udpHistoryPacket(peer, client))
	flushed := make(chan struct{})
	go func() { host.Flush(); close(flushed) }()
	pendingReceive(t, origin.entered)
	reset := make(chan struct{})
	go func() { host.dispatcher.ResetNetwork(); source.dispatcher.ResetNetwork(); close(reset) }()
	pendingReceive(t, reset)
	release()
	pendingReceive(t, flushed)
}

func TestRoutedReturnPreservesDataBeforeTCPReset(t *testing.T) {
	origin := &recordingReturnWriter{paddedReturnWriter: paddedReturnWriter{pendingWriteback{packets: make(chan []byte, 4)}}}
	source, host, port := newRoutedTestPath(t, origin, nil)
	client, peer := netip.MustParseAddrPort("10.0.0.2:50000"), netip.MustParseAddrPort("203.0.113.1:443")
	packet := func(from, to netip.AddrPort, flags header.TCPFlags, payload string) []byte {
		ip := header.IPv4(make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize+len(payload)))
		ip.Encode(&header.IPv4Fields{TotalLength: uint16(len(ip)), TTL: 64, Protocol: uint8(header.TCPProtocolNumber), SrcAddr: from.Addr(), DstAddr: to.Addr()})
		tcp := header.TCP(ip.Payload())
		tcp.Encode(&header.TCPFields{SrcPort: from.Port(), DstPort: to.Port(), DataOffset: header.TCPMinimumSize, Flags: flags, WindowSize: 65535})
		copy(tcp.Payload(), payload)
		parsed, ok := parseForwardPacket(ip)
		require.True(t, ok)
		recomputeChecksums(&parsed)
		return ip
	}
	require.True(t, source.Dispatch(packet(client, peer, header.TCPFlagSyn, "")))
	source.Flush()
	pendingReceive(t, port.sent)
	stageRoutedReply(t, host, packet(peer, client, header.TCPFlagAck, "last data"))
	stageRoutedReply(t, host, packet(peer, client, header.TCPFlagRst, ""))
	host.Flush()
	require.Equal(t, []int{2}, origin.batches)
	next := func() header.TCP {
		return header.TCP(header.IPv4(pendingReceive(t, origin.packets)[origin.ReturnHeadroom():]).Payload())
	}
	require.Equal(t, "last data", string(next().Payload()))
	require.Equal(t, header.TCPFlagRst, next().Flags())
	stageRoutedReply(t, host, packet(peer, client, header.TCPFlagAck, "late"))
	host.Flush()
	require.Empty(t, origin.packets)
}

type countReturnWrites struct {
	udpHistoryWriteback
	calls int
}

func (w *countReturnWrites) WriteReturnPackets([][]byte) error {
	w.calls++
	return nil
}

func BenchmarkRoutedReturnBatch(b *testing.B) {
	origin := new(countReturnWrites)
	source, host, port := newRoutedTestPath(b, origin, nil)
	client, peer := netip.MustParseAddrPort("10.0.0.2:50000"), netip.MustParseAddrPort("203.0.113.1:443")
	require.True(b, source.Dispatch(udpHistoryPacket(client, peer)))
	source.Flush()
	<-port.sent
	reply := udpHistoryPacket(peer, client)
	const batchSize = 32
	b.ReportAllocs()
	b.SetBytes(batchSize * int64(len(reply)))
	for b.Loop() {
		for range batchSize {
			parsed, ok := parseForwardPacket(reply)
			if !ok || !host.ReturnParsed(reply, ForwardFrameMeta{}, &parsed) {
				b.Fatal("routed reply was lost")
			}
		}
		host.Flush()
	}
	b.ReportMetric(float64(origin.calls)/float64(b.N), "writes/batch")
}
