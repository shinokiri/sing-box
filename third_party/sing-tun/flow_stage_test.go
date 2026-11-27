package tun

import (
	"bytes"
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	"github.com/stretchr/testify/require"
)

type stagedUDPPort struct {
	udpHistoryPort
	access  sync.Mutex
	packets []UDPFlowPacket
}

func (p *stagedUDPPort) WriteUDPFlowPackets(packets []UDPFlowPacket) error {
	p.access.Lock()
	defer p.access.Unlock()
	for _, packet := range packets {
		if packet.Flow.IsActive() {
			p.packets = append(p.packets, UDPFlowPacket{Packet: bytes.Clone(packet.Packet), Flow: packet.Flow})
		}
	}
	return nil
}

func TestForwardStagesKeepBatchesAndSocketOwnershipSeparate(t *testing.T) {
	port := new(stagedUDPPort)
	d := NewForwardDispatcher(udpHistoryHandler{port: port}, udpHistoryWriteback{}, logger.NOP(), time.Minute, time.Minute)
	t.Cleanup(d.Close)
	stages := []*ForwardStage{d.NewStage(nil), d.NewStage(nil)}
	var wg sync.WaitGroup
	for index, stage := range stages {
		wg.Go(func() {
			client := netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, byte(index + 2)}), 50000)
			for i := range 64 {
				raw := udpHistoryPacket(client, netip.AddrPortFrom(netip.MustParseAddr("203.0.113.1"), uint16(1000+i)))
				parsed, ok := parseForwardPacket(raw)
				require.True(t, ok)
				require.True(t, stage.DispatchParsed(raw, ForwardFrameMeta{}, &parsed))
				clear(raw) // A Go queue immediately reuses this borrowed frame.
			}
		})
	}
	wg.Wait()
	stages[0].Flush()
	require.Len(t, port.packets, 64, "one stage must not flush another stage's batch")
	stages[1].Flush()
	require.Len(t, port.packets, 128)
	mappings := make(map[UDPMapping]netip.AddrPort)
	for _, packet := range port.packets {
		parsed, ok := parseForwardPacket(packet.Packet)
		require.True(t, ok, "borrowed frame was overwritten")
		mapping := packet.Flow.UDPMapping().(*udpMapping)
		require.Equal(t, mapping.source, parsed.source)
		mappings[mapping] = mapping.client
	}
	require.Len(t, mappings, 2, "same source port from different clients must stay isolated")
	d.ResetNetwork()
	for mapping := range mappings {
		require.False(t, mapping.IsActive())
		require.ErrorIs(t, mapping.Context().Err(), context.Canceled)
	}
}

// Construct the real Go engine without a kernel TUN. Only wake is needed to
// exercise its asynchronous handoff; the owner drains the injected frame.
type pendingGoIO struct{ goPlatformIO }

func (*pendingGoIO) wake()               {}
func (*pendingGoIO) transmitPrefix() int { return 0 }

func TestGoEngineDefersRoutingAndHandsAcceptedVerdictBack(t *testing.T) {
	entered, unblock := make(chan struct{}), make(chan struct{})
	handler := &pendingHandler{judge: func(ctx context.Context, _ netip.AddrPort, _ []byte) FlowVerdict {
		close(entered)
		select {
		case <-unblock:
		case <-ctx.Done():
		}
		return FlowVerdict{Action: ActionAccept, UDPTimeout: 37 * time.Second}
	}}
	stack, err := NewGo(StackOptions{Context: t.Context(), Handler: handler, Logger: logger.NOP()})
	require.NoError(t, err)
	stack.dispatcher = NewForwardDispatcher(handler, udpHistoryWriteback{}, logger.NOP(), time.Minute, time.Minute)
	t.Cleanup(stack.dispatcher.Close)
	engine := newGoEngine(stack, new(pendingGoIO), 1)
	t.Cleanup(engine.releaseInjected)
	raw := pendingPacket(50000, []byte("retained"))
	engine.processFrame(&goFrame{buffer: buf.As(raw)})
	pendingReceive(t, entered)
	clear(raw)
	close(unblock)
	waitPendingIdle(t, engine.dispatchStage.dispatcher)
	frame := engine.injectStack.popAll()
	require.NotNil(t, frame)
	defer frame.buffer.Release()
	parsed, ok := parseForwardPacket(frame.buffer.Bytes())
	require.True(t, ok)
	require.Equal(t, "retained", string(header.UDP(parsed.transport).Payload()))
	require.False(t, engine.dispatchStage.DispatchParsed(frame.buffer.Bytes(), frame.meta, &parsed))
	require.Equal(t, 37*time.Second, parsed.verdict.UDPTimeout)
	stack.closed.Store(true)
	engine.injectFlowPacket(pendingPacket(50001, []byte("closed")), ForwardFrameMeta{})
	require.Nil(t, engine.injectStack.popAll(), "shutdown must stop late asynchronous handoffs")
}

func TestForwardStageIdleSweepKeepsWorkerTablesIndependent(t *testing.T) {
	var absent *ForwardStage
	remaining, pending := absent.sweepDue()
	require.Zero(t, remaining)
	require.False(t, pending)

	port := new(stagedUDPPort)
	d := NewForwardDispatcher(udpHistoryHandler{port: port}, udpHistoryWriteback{}, logger.NOP(), time.Minute, time.Minute)
	t.Cleanup(d.Close)
	active, idle := d.NewStage(nil), d.NewStage(nil)
	_, pending = active.sweepDue()
	require.False(t, pending, "an empty worker must not schedule idle wakeups")

	packet := udpHistoryPacket(netip.MustParseAddrPort("10.0.0.2:50000"), netip.MustParseAddrPort("203.0.113.2:53"))
	require.True(t, active.Dispatch(packet))
	active.Flush()
	require.Len(t, port.packets, 1)
	flow := port.packets[0].Flow
	require.True(t, flow.IsActive())
	remaining, pending = active.sweepDue()
	require.True(t, pending)
	require.Positive(t, remaining)
	require.LessOrEqual(t, remaining, flowSweepInterval)
	_, pending = idle.sweepDue()
	require.False(t, pending, "another worker's traffic must not arm this worker")

	// Advance only this worker's monotonic test clock, without waiting for TTLs.
	active.dispatcher.epoch = time.Now().Add(-3 * time.Minute)
	remaining, pending = active.sweepDue()
	require.True(t, pending)
	require.Zero(t, remaining)
	active.Flush()
	require.False(t, flow.IsActive(), "the scheduled sweep must retire an expired idle flow")
	_, pending = active.sweepDue()
	require.False(t, pending, "a drained worker must stop scheduling sweeps")
}

func TestForwardStagePendingVerdictKeepsIdleSweepScheduled(t *testing.T) {
	entered, unblock := make(chan struct{}), make(chan struct{})
	handler := &pendingHandler{judge: func(ctx context.Context, _ netip.AddrPort, _ []byte) FlowVerdict {
		close(entered)
		select {
		case <-unblock:
		case <-ctx.Done():
		}
		return FlowVerdict{Action: ActionDrop}
	}}
	// Drop verdicts use the protocol idle timeout, not RejectTimeout.
	d := NewForwardDispatcher(handler, udpHistoryWriteback{}, logger.NOP(), time.Second, time.Second)
	t.Cleanup(d.Close)
	d.EnableAsyncFlow(t.Context(), nil)
	stage := d.NewStage(nil)
	require.True(t, stage.Dispatch(pendingPacket(50000, []byte("pending"))))
	pendingReceive(t, entered)

	// The Go engine may sleep before DNS/routing produces a table entry.
	// Its existing sweep timer must stay armed for the eventual verdict.
	remaining, pending := stage.sweepDue()
	require.True(t, pending)
	require.Positive(t, remaining)
	close(unblock)
	waitPendingIdle(t, d)
	_, pending = stage.sweepDue()
	require.True(t, pending)

	d.epoch = d.epoch.Add(-2 * flowSweepInterval)
	stage.Flush()
	_, pending = stage.sweepDue()
	require.False(t, pending, "the delayed drop verdict must expire without another packet")
}

func TestSocketFlowReturnsDatagramsAtIngressMTU(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version uint8
		client  string
		peer    string
	}{
		{"IPv4", 4, "10.0.0.2:50000", "203.0.113.1:443"},
		{"IPv6", 6, "[fd00::2]:50000", "[2001:db8::1]:443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			port := new(stagedUDPPort)
			d := NewForwardDispatcher(udpHistoryHandler{port: port}, udpHistoryWriteback{}, logger.NOP(), time.Minute, time.Minute)
			t.Cleanup(d.Close)
			d.mtu = 1280
			d.NewStage(nil)
			origin := &paddedReturnWriter{pendingWriteback{packets: make(chan []byte, 4)}}
			stage := d.NewStage(origin)
			client, peer := netip.MustParseAddrPort(tc.client), netip.MustParseAddrPort(tc.peer)
			datagram := func(from, to netip.AddrPort, payload []byte) []byte {
				wire := make([]byte, goNetworkHeaderLength(tc.version)+header.UDPMinimumSize+len(payload))
				goEncodeUDPPacket(wire, tc.version, from, to, payload, 7)
				return wire
			}
			payload := bytes.Repeat([]byte("large-datagram"), 160)
			require.True(t, stage.Dispatch(datagram(client, peer, payload)))
			stage.Flush()
			require.Len(t, port.packets, 1)
			sent, ok := parseForwardPacket(port.packets[0].Packet)
			require.True(t, ok)
			require.False(t, sent.fragment)
			require.Equal(t, payload, header.UDP(sent.transport).Payload())
			mapping := port.packets[0].Flow.UDPMapping()
			for _, reply := range [][]byte{[]byte("small"), payload} {
				require.True(t, mapping.ReturnPacket(datagram(peer, sent.source, reply)))
				var transport []byte
				for {
					wire := pendingReceive(t, origin.packets)[origin.ReturnHeadroom():]
					require.LessOrEqual(t, len(wire), int(d.mtu))
					frame, ok := parseForwardPacket(wire)
					require.True(t, ok)
					require.Equal(t, client.Addr(), frame.destination.Addr())
					require.Equal(t, peer.Addr(), frame.source.Addr())
					if !frame.fragment {
						transport = frame.transport
						break
					}
					require.Equal(t, len(transport), frame.fragmentInfo.offset)
					transport = append(transport, wire[len(wire)-frame.fragmentInfo.length:]...)
					if !frame.fragmentInfo.more {
						break
					}
				}
				udp := header.UDP(transport)
				require.Equal(t, client.Port(), udp.DestinationPort())
				require.Equal(t, reply, udp.Payload())
			}
		})
	}
}
