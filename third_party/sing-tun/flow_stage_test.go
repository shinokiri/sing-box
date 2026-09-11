package tun

import (
	"bytes"
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"
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
	stack := NewGo(StackOptions{Context: t.Context(), Handler: handler, Logger: logger.NOP()})
	stack.dispatcher = NewForwardDispatcher(handler, udpHistoryWriteback{}, logger.NOP(), time.Minute, time.Minute)
	t.Cleanup(stack.dispatcher.Close)
	engine := newGoEngine(stack, new(pendingGoIO), 1)
	t.Cleanup(engine.releaseInjected)
	raw := pendingPacket(50000, []byte("retained"))
	engine.processFrame(&goFrame{data: raw})
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
	engine.injectFlowPacket(pendingPacket(50001, []byte("closed")))
	require.Nil(t, engine.injectStack.popAll(), "shutdown must stop late asynchronous handoffs")
}
