//go:build with_gvisor

package tun

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	gHdr "github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

type pendingTun struct {
	ctx       context.Context
	read      chan []byte
	written   chan []byte
	closed    chan struct{}
	closeOnce sync.Once
	endpoint  *channel.Endpoint
}

func (t *pendingTun) Read(b []byte) (int, error) {
	select {
	case packet := <-t.read:
		return copy(b, packet), nil
	case <-t.closed:
		return 0, net.ErrClosed
	}
}
func (t *pendingTun) Write(b []byte) (int, error) {
	select {
	case t.written <- append([]byte(nil), b...):
		return len(b), nil
	case <-t.closed:
		return 0, net.ErrClosed
	}
}
func (*pendingTun) Name() (string, error)            { return "pending-test", nil }
func (*pendingTun) Start() error                     { return nil }
func (t *pendingTun) Close() error                   { t.closeOnce.Do(func() { close(t.closed) }); return nil }
func (*pendingTun) UpdateRouteOptions(Options) error { return nil }
func (t *pendingTun) WritePacket(pkt *stack.PacketBuffer) (int, error) {
	view := pkt.ToView()
	defer view.Release()
	return t.Write(view.AsSlice())
}
func (t *pendingTun) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	t.endpoint = channel.New(32, 1500, "")
	go func() {
		for {
			pkt := t.endpoint.ReadContext(t.ctx)
			if pkt == nil {
				return
			}
			t.WritePacket(pkt)
			pkt.DecRef()
		}
	}()
	return t.endpoint, stack.NICOptions{}, nil
}

type pendingStackHandler struct {
	*pendingHandler
	packets     chan string
	connections chan struct{}
}

func (h *pendingStackHandler) NewConnectionEx(_ context.Context, conn net.Conn, _, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.connections <- struct{}{}
	conn.Close()
	if onClose != nil {
		onClose(nil)
	}
}

func newPendingStack(t *testing.T, name string, handler *pendingStackHandler) (Stack, *pendingTun, func([]byte)) {
	t.Helper()
	device := &pendingTun{ctx: t.Context(), read: make(chan []byte, 8), written: make(chan []byte, 32), closed: make(chan struct{})}
	t.Cleanup(func() { device.Close() })
	instance, err := NewStack(name, StackOptions{Context: t.Context(), Tun: device, TunOptions: Options{MTU: 1500, Inet4Address: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/30")}}, UDPTimeout: time.Minute, Handler: handler, Logger: logger.NOP()})
	require.NoError(t, err)
	t.Cleanup(func() { instance.Close() })
	require.NoError(t, instance.Start())
	return instance, device, func(raw []byte) {
		if name == "gvisor" {
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(raw)})
			device.endpoint.InjectInbound(tcpip.NetworkProtocolNumber(gHdr.IPv4ProtocolNumber), pkt)
			pkt.DecRef()
		} else {
			device.read <- raw
		}
	}
}

func (h *pendingStackHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, _, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer conn.Close()
	if onClose != nil {
		defer onClose(nil)
	}
	for {
		buffer := buf.NewSize(1500)
		_, err := conn.ReadPacket(buffer)
		if err != nil {
			buffer.Release()
			return
		}
		payload := string(buffer.Bytes())
		buffer.Release()
		select {
		case h.packets <- payload:
		case <-ctx.Done():
			return
		}
	}
}

// Use each real stack with an in-memory TUN. This exercises the setup wiring
// and normal UDP fallback, including gVisor's second pre-match entry point.
func TestStacksDeferRoutingAndDeliverOrdinaryUDP(t *testing.T) {
	for _, name := range []string{"system", "mixed", "gvisor"} {
		t.Run(name, func(t *testing.T) {
			port := &pendingPort{sent: make(chan []byte, 8)}
			started, resume := make(chan struct{}, 1), make(chan struct{})
			release := sync.OnceFunc(func() { close(resume) })
			defer release()
			handler := &pendingStackHandler{packets: make(chan string, 8), pendingHandler: &pendingHandler{judge: func(ctx context.Context, source netip.AddrPort, _ []byte) FlowVerdict {
				if source.Port() == 50000 {
					started <- struct{}{}
					select {
					case <-resume:
					case <-ctx.Done():
					}
					return FlowVerdict{Action: ActionAccept}
				}
				return FlowVerdict{Action: ActionFlow, Port: port}
			}}}
			_, _, inject := newPendingStack(t, name, handler)
			inject(pendingPacket(50000, []byte("first")))
			pendingReceive(t, started)
			inject(pendingPacket(50000, []byte("second")))
			inject(pendingPacket(50001, []byte("independent")))
			pendingReceive(t, port.sent)
			release()
			require.Equal(t, "first", pendingReceive(t, handler.packets))
			require.Equal(t, "second", pendingReceive(t, handler.packets))
			inject(pendingPacket(50000, []byte("third")))
			require.Equal(t, "third", pendingReceive(t, handler.packets))
		})
	}
}

func TestStacksOrdinaryTCPAndICMPAfterAsyncRouting(t *testing.T) {
	for _, name := range []string{"system", "mixed", "gvisor"} {
		for _, protocol := range []uint8{uint8(header.TCPProtocolNumber), uint8(header.ICMPv4ProtocolNumber)} {
			label := "TCP"
			if protocol == uint8(header.ICMPv4ProtocolNumber) {
				label = "ICMP"
			}
			t.Run(name+"/"+label, func(t *testing.T) {
				handler := &pendingStackHandler{connections: make(chan struct{}, 1), pendingHandler: &pendingHandler{judge: func(context.Context, netip.AddrPort, []byte) FlowVerdict { return FlowVerdict{Action: ActionAccept} }}}
				_, device, inject := newPendingStack(t, name, handler)
				transportSize := header.TCPMinimumSize
				if protocol == uint8(header.ICMPv4ProtocolNumber) {
					transportSize = header.ICMPv4MinimumSize
				}
				ip := header.IPv4(make([]byte, header.IPv4MinimumSize+transportSize))
				ip.Encode(&header.IPv4Fields{TotalLength: uint16(len(ip)), TTL: 64, Protocol: protocol, SrcAddr: netip.MustParseAddr("10.0.0.2"), DstAddr: netip.MustParseAddr("203.0.113.1")})
				if protocol == uint8(header.TCPProtocolNumber) {
					tcp := header.TCP(ip.Payload())
					tcp.Encode(&header.TCPFields{SrcPort: 50000, DstPort: 443, SeqNum: 1, DataOffset: header.TCPMinimumSize, Flags: header.TCPFlagSyn, WindowSize: 65535})
					tcp.SetChecksum(^tcp.CalculateChecksum(header.PseudoHeaderChecksum(header.TCPProtocolNumber, ip.SourceAddressSlice(), ip.DestinationAddressSlice(), uint16(transportSize))))
				} else {
					icmp := header.ICMPv4(ip.Payload())
					icmp.SetType(header.ICMPv4Echo)
					icmp.SetIdent(50000)
					icmp.SetChecksum(header.ICMPv4Checksum(icmp, 0))
				}
				ip.SetChecksum(^ip.CalculateChecksum())
				inject(ip)
				if protocol == uint8(header.TCPProtocolNumber) && name == "gvisor" {
					pendingReceive(t, handler.connections)
				} else {
					response := header.IPv4(pendingReceive(t, device.written))
					require.Equal(t, protocol, uint8(response.TransportProtocol()))
					if protocol == uint8(header.ICMPv4ProtocolNumber) {
						require.Equal(t, header.ICMPv4EchoReply, header.ICMPv4(response.Payload()).Type())
					} else {
						require.True(t, header.TCP(response.Payload()).Flags().Contains(header.TCPFlagSyn))
					}
				}
			})
		}
	}
}
