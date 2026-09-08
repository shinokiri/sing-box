package tun

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/checksum"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

type pendingHandler struct {
	Handler
	judge func(context.Context, netip.AddrPort, []byte) FlowVerdict
	dns   chan []byte
}

func (h *pendingHandler) JudgeFlowContext(ctx context.Context, _ uint8, source, _ netip.AddrPort, first []byte) FlowVerdict {
	return h.judge(ctx, source, first)
}

func (*pendingHandler) JudgeFlow(uint8, netip.AddrPort, netip.AddrPort, []byte) FlowVerdict {
	panic("async dispatch must not run synchronous routing")
}

func (h *pendingHandler) NewDNSPacket(payload []byte, _, _ M.Socksaddr, _ N.PacketWriter) {
	h.dns <- append([]byte(nil), payload...)
}

type pendingPort struct {
	Port
	sent chan []byte
}

func (*pendingPort) PortAddresses() (netip.Addr, netip.Addr) {
	return netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("fd01::1")
}
func (*pendingPort) PortMTU() uint32           { return 0 }
func (*pendingPort) AttachReturn(Return) error { return nil }
func (*pendingPort) DetachReturn(Return) error { return nil }
func (p *pendingPort) WritePackets(packets [][]byte) error {
	for _, raw := range packets {
		p.sent <- append([]byte(nil), raw...)
	}
	return nil
}

type pendingWriteback struct{ packets chan []byte }

func (*pendingWriteback) ReturnHeadroom() int { return 0 }
func (w *pendingWriteback) WriteReturnPackets(packets [][]byte) error {
	for _, raw := range packets {
		w.packets <- append([]byte(nil), raw...)
	}
	return nil
}

func pendingPacket(selector uint16, payload []byte) []byte {
	ip := header.IPv4(make([]byte, 28+len(payload)))
	ip.Encode(&header.IPv4Fields{TotalLength: uint16(len(ip)), TTL: 64, Protocol: uint8(header.UDPProtocolNumber), SrcAddr: netip.MustParseAddr("10.0.0.2"), DstAddr: netip.MustParseAddr("203.0.113.1")})
	udp := header.UDP(ip.Payload())
	udp.Encode(&header.UDPFields{SrcPort: selector, DstPort: 443, Length: uint16(8 + len(payload))})
	copy(udp.Payload(), payload)
	udp.SetChecksum(^checksum.Checksum(udp.Payload(), udp.CalculateChecksum(header.PseudoHeaderChecksum(header.UDPProtocolNumber, ip.SourceAddressSlice(), ip.DestinationAddressSlice(), udp.Length()))))
	ip.SetChecksum(^ip.CalculateChecksum())
	return ip
}

func pendingReceive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for pending flow")
		var zero T
		return zero
	}
}

func waitPendingIdle(t *testing.T, d *ForwardDispatcher) {
	t.Helper()
	require.Eventually(t, func() bool {
		d.access.Lock()
		defer d.access.Unlock()
		return d.async.workers == 0 && d.async.bytes == 0 && len(d.async.pending) == 0
	}, 3*time.Second, time.Millisecond)
}

func TestPendingFlowLimitsLeaveEstablishedFlowsUsable(t *testing.T) {
	for _, kind := range []string{"flows", "packets", "bytes"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			port := &pendingPort{sent: make(chan []byte, 2048)}
			started := make(chan struct{}, pendingFlowLimit)
			var lookups atomic.Int32
			handler := &pendingHandler{judge: func(ctx context.Context, source netip.AddrPort, _ []byte) FlowVerdict {
				if source.Port() != 50000 {
					lookups.Add(1)
					started <- struct{}{}
					<-ctx.Done()
				}
				return FlowVerdict{Action: ActionFlow, Port: port}
			}}
			d := NewForwardDispatcher(handler, &pendingWriteback{packets: make(chan []byte, 8)}, logger.NOP(), time.Minute, time.Minute)
			d.EnableAsyncFlow(ctx, func([]byte) { t.Error("unexpected fallback") })
			defer d.Close()
			require.True(t, d.Dispatch(pendingPacket(50000, []byte("establish"))))
			pendingReceive(t, port.sent)
			waitPendingIdle(t, d)
			flows, packets, size := pendingFlowLimit, 1, 29
			if kind == "packets" {
				flows, packets = 1, pendingPacketLimit
			}
			if kind == "bytes" {
				flows, packets, size = 16, pendingPacketLimit, 4096
			}
			for i := 0; i < flows; i++ {
				for j := 0; j < packets; j++ {
					require.True(t, d.Dispatch(pendingPacket(uint16(10000+i), make([]byte, size-28))))
				}
			}
			for range flows {
				pendingReceive(t, started)
			}
			selector := uint16(20000)
			if kind == "packets" {
				selector = 10000
			}
			require.True(t, d.Dispatch(pendingPacket(selector, make([]byte, size-28))))
			require.True(t, d.Dispatch(pendingPacket(50000, []byte("still moving"))))
			d.Flush()
			require.Equal(t, "still moving", string(header.UDP(header.IPv4(pendingReceive(t, port.sent)).Payload()).Payload()))
			d.access.Lock()
			workers, heldBytes := d.async.workers, d.async.bytes
			d.access.Unlock()
			require.Equal(t, flows, workers)
			require.Equal(t, flows*packets*size, heldBytes)
			d.Close()
			waitPendingIdle(t, d)
			require.Equal(t, int32(flows), lookups.Load())
		})
	}
}

func TestPendingResetDiscardsLateVerdictAndPreservesWorkerBudget(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	port := &pendingPort{sent: make(chan []byte, 8)}
	started := make(chan context.Context, 2)
	resume := make(chan struct{})
	release := sync.OnceFunc(func() { close(resume) })
	defer release()
	var calls atomic.Int32
	h := &pendingHandler{judge: func(ctx context.Context, _ netip.AddrPort, _ []byte) FlowVerdict {
		if calls.Add(1) == 1 {
			started <- ctx
			<-resume
		}
		return FlowVerdict{Action: ActionFlow, Port: port}
	}}
	d := NewForwardDispatcher(h, &pendingWriteback{}, logger.NOP(), time.Minute, time.Minute)
	d.EnableAsyncFlow(ctx, func([]byte) { t.Error("unexpected fallback") })
	defer d.Close()
	d.Dispatch(pendingPacket(50000, []byte("old")))
	oldContext := pendingReceive(t, started)
	d.ResetNetwork()
	require.ErrorIs(t, oldContext.Err(), context.Canceled)
	d.access.Lock()
	workers := d.async.workers
	d.access.Unlock()
	require.Equal(t, 1, workers, "a canceled lookup still counts until it exits")
	d.Dispatch(pendingPacket(50000, []byte("new")))
	raw := pendingReceive(t, port.sent)
	require.Equal(t, "new", string(header.UDP(header.IPv4(raw).Payload()).Payload()))
	release()
	waitPendingIdle(t, d)
	require.Empty(t, port.sent, "a late old verdict must not forward its packet")
}

func TestPendingOrdinaryFallbackPreservesOrderWithoutHoldingDispatcher(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	port := &pendingPort{sent: make(chan []byte, 8)}
	entered, resume := make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(resume) })
	defer release()
	accepted := make(chan string, 4)
	h := &pendingHandler{judge: func(_ context.Context, source netip.AddrPort, _ []byte) FlowVerdict {
		if source.Port() == 50000 {
			return FlowVerdict{Action: ActionAccept}
		}
		return FlowVerdict{Action: ActionFlow, Port: port}
	}}
	d := NewForwardDispatcher(h, &pendingWriteback{}, logger.NOP(), time.Minute, time.Minute)
	d.EnableAsyncFlow(ctx, func(raw []byte) {
		payload := string(header.UDP(header.IPv4(raw).Payload()).Payload())
		if payload == "first" {
			close(entered)
			<-resume
		}
		accepted <- payload
	})
	defer d.Close()
	d.Dispatch(pendingPacket(50000, []byte("first")))
	pendingReceive(t, entered)
	for _, payload := range []string{"second", "third"} {
		d.Dispatch(pendingPacket(50000, []byte(payload)))
	}
	d.Dispatch(pendingPacket(50001, []byte("independent")))
	pendingReceive(t, port.sent)
	release()
	for _, payload := range []string{"first", "second", "third"} {
		require.Equal(t, payload, pendingReceive(t, accepted))
	}
	waitPendingIdle(t, d)
	require.False(t, d.Dispatch(pendingPacket(50000, []byte("inline"))), "later ordinary packets use the original stack path")
}

func TestPendingVerdicts(t *testing.T) {
	for _, action := range []FlowAction{ActionReject, ActionDrop, ActionHijackDNS, ActionBypass} {
		t.Run([]string{"flow", "accept", "reject", "drop", "bypass", "dns"}[action], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			h := &pendingHandler{dns: make(chan []byte, 2), judge: func(context.Context, netip.AddrPort, []byte) FlowVerdict { return FlowVerdict{Action: action} }}
			w := &pendingWriteback{packets: make(chan []byte, 2)}
			accepted := make(chan []byte, 2)
			d := NewForwardDispatcher(h, w, logger.NOP(), time.Minute, time.Minute)
			d.EnableAsyncFlow(ctx, func(raw []byte) { accepted <- raw })
			defer d.Close()
			d.Dispatch(pendingPacket(50000, []byte("query")))
			waitPendingIdle(t, d)
			switch action {
			case ActionReject:
				require.Len(t, w.packets, 1)
			case ActionDrop:
				require.Empty(t, w.packets)
				require.Empty(t, accepted)
			case ActionHijackDNS:
				require.Equal(t, []byte("query"), pendingReceive(t, h.dns))
			case ActionBypass:
				require.Len(t, accepted, 1)
			}
		})
	}
}

func TestPendingParentCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{}, 1)
	h := &pendingHandler{judge: func(ctx context.Context, _ netip.AddrPort, _ []byte) FlowVerdict {
		started <- struct{}{}
		<-ctx.Done()
		return FlowVerdict{Action: ActionAccept}
	}}
	d := NewForwardDispatcher(h, &pendingWriteback{}, logger.NOP(), time.Minute, time.Minute)
	d.EnableAsyncFlow(ctx, func([]byte) { t.Error("canceled packet reached the stack") })
	defer d.Close()
	d.Dispatch(pendingPacket(50000, []byte("query")))
	pendingReceive(t, started)
	cancel()
	waitPendingIdle(t, d)
}
