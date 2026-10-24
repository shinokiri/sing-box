package tun

import (
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/logger"
	"github.com/stretchr/testify/require"
)

func TestForwardAbortedFlowCanBeRoutedAgain(t *testing.T) {
	for _, sweep := range []bool{false, true} {
		name := "next-packet"
		if sweep {
			name = "idle-sweep"
		}
		t.Run(name, func(t *testing.T) {
			port := newReservedFlowPort()
			port.ranges = []SelectorRange{{Start: 50000, Count: 8}}
			d := NewForwardDispatcher(udpHistoryHandler{port: port}, udpHistoryWriteback{}, logger.NOP(), time.Minute, time.Minute)
			t.Cleanup(d.Close)
			client := netip.MustParseAddrPort("10.0.0.2:50000")
			peer := netip.MustParseAddrPort("203.0.113.1:443")
			key := flowKey{protocol: uint8(header.UDPProtocolNumber), source: client, destination: peer}
			require.True(t, d.Dispatch(udpHistoryPacket(client, peer)))
			d.Flush()
			pendingReceive(t, port.sent)
			first := d.table[key].flow
			first.CloseFlow()
			if sweep {
				d.epoch = d.epoch.Add(-31 * time.Second)
				d.Flush()
				require.NotContains(t, d.table, key)
				require.Empty(t, port.held)
			}
			require.True(t, d.Dispatch(udpHistoryPacket(client, peer)))
			d.Flush()
			pendingReceive(t, port.sent)
			require.NotSame(t, first, d.table[key].flow)
			require.True(t, d.table[key].flow.IsActive())
			require.Len(t, port.held, 1)
		})
	}
}

type alpha13AcceptHandler struct {
	Handler
	calls int
}

func (h *alpha13AcceptHandler) JudgeFlow(uint8, netip.AddrPort, netip.AddrPort, []byte) FlowVerdict {
	h.calls++
	return FlowVerdict{Action: ActionAccept, UDPTimeout: 37 * time.Second}
}

func TestForwardAcceptTCPDecisionEndsAfterHandshake(t *testing.T) {
	h := new(alpha13AcceptHandler)
	d := NewForwardDispatcher(h, udpHistoryWriteback{}, logger.NOP(), time.Minute, time.Minute)
	t.Cleanup(d.Close)
	packet := func(flags header.TCPFlags) []byte {
		ip := header.IPv4(make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize))
		ip.Encode(&header.IPv4Fields{TotalLength: uint16(len(ip)), TTL: 64, Protocol: uint8(header.TCPProtocolNumber), SrcAddr: netip.MustParseAddr("10.0.0.2"), DstAddr: netip.MustParseAddr("203.0.113.1")})
		header.TCP(ip.Payload()).Encode(&header.TCPFields{SrcPort: 50000, DstPort: 443, DataOffset: header.TCPMinimumSize, Flags: flags, WindowSize: 65535})
		return ip
	}
	require.False(t, d.Dispatch(packet(header.TCPFlagSyn)))
	require.False(t, d.Dispatch(packet(header.TCPFlagSyn)))
	require.Equal(t, 1, h.calls, "retransmitted SYN should reuse the decision")
	require.False(t, d.Dispatch(packet(header.TCPFlagAck)))
	require.Empty(t, d.table, "established TCP sessions are owned by the stack")
	require.False(t, d.Dispatch(packet(header.TCPFlagSyn)))
	require.Equal(t, 2, h.calls, "a new session must get a fresh decision")
}

func TestForwardStackFallbackKeepsAcceptedVerdictOptions(t *testing.T) {
	h := new(alpha13AcceptHandler)
	d := NewForwardDispatcher(h, udpHistoryWriteback{}, logger.NOP(), time.Minute, time.Minute)
	t.Cleanup(d.Close)
	client := netip.MustParseAddrPort("10.0.0.2:50000")
	peer := netip.MustParseAddrPort("203.0.113.1:443")
	require.False(t, d.Dispatch(udpHistoryPacket(client, peer)))
	verdict := d.judgeFlowForStack(h, uint8(header.UDPProtocolNumber), client, peer, nil)
	require.Equal(t, ActionAccept, verdict.Action)
	require.Equal(t, 37*time.Second, verdict.UDPTimeout)
	require.Equal(t, 1, h.calls, "the stack must reuse the full original decision")
}
