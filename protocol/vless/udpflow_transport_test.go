package vless

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/udpflow"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2ray"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

type flowTransportDialer struct{ N.Dialer }

func (*flowTransportDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, destination.String())
}

type flowEchoHandler struct {
	service *vless.Service[string]
	calls   atomic.Int32
}

func (h *flowEchoHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.calls.Add(1)
	go func() {
		err := h.service.NewConnection(ctx, conn, source, nil)
		conn.Close()
		if onClose != nil {
			onClose(err)
		}
	}()
}

func (*flowEchoHandler) NewPacketConnectionEx(_ context.Context, conn N.PacketConn, _, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	go func() {
		defer conn.Close()
		for {
			buffer := buf.NewSize(65535)
			destination, err := conn.ReadPacket(buffer)
			if err != nil {
				buffer.Release()
				return
			}
			if _, err = bufio.WritePacketBuffer(conn, buffer, destination); err != nil {
				return
			}
		}
	}()
}

type flowTransportReturn struct{ packets chan []byte }

func (*flowTransportReturn) ReturnHeadroom() int { return 0 }

func (r *flowTransportReturn) ReturnPackets(packets [][]byte) [][]byte {
	for _, packet := range packets {
		r.packets <- append([]byte(nil), packet...)
	}
	return nil
}

// Use the real VLESS factory and gRPC transport: these streams retain their
// dial context after setup, unlike a plain TCP connection or net.Pipe.
func TestXUDPFlowOverGRPC(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	const user = "b831381d-6324-4d53-ad4f-8cda48b30811"
	handler := &flowEchoHandler{}
	handler.service = vless.NewService[string](logger.NOP(), handler)
	handler.service.UpdateUsers([]string{"test"}, []string{user}, []string{""})
	options := option.V2RayTransportOptions{Type: "grpc", GRPCOptions: option.V2RayGRPCOptions{ServiceName: "udpflow"}}
	server, err := v2ray.NewServerTransport(ctx, logger.NOP(), options, nil, handler)
	require.NoError(t, err)
	defer server.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	go server.Serve(listener)
	transport, err := v2ray.NewClientTransport(ctx, &flowTransportDialer{}, M.SocksaddrFromNet(listener.Addr()), options, nil)
	require.NoError(t, err)
	defer transport.Close()
	client, err := vless.NewClient(user, "", logger.NOP())
	require.NoError(t, err)
	outbound := &Outbound{logger: logger.NOP(), client: client, transport: transport}
	port, err := udpflow.New(udpflow.Options{Context: ctx, DialPacketConn: outbound.dialXUDPFlowPacketConn})
	require.NoError(t, err)
	defer port.Close()
	returnPath := &flowTransportReturn{packets: make(chan []byte, 4)}
	require.NoError(t, port.AttachReturn(returnPath))
	internal, _ := port.PortAddresses()
	for _, destination := range []string{"203.0.113.1", "203.0.113.2"} {
		address := netip.MustParseAddr(destination)
		payload := []byte(destination)
		packet := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize+len(payload))
		ip := header.IPv4(packet)
		ip.Encode(&header.IPv4Fields{TotalLength: uint16(len(packet)), TTL: 64, Protocol: uint8(header.UDPProtocolNumber), SrcAddr: internal, DstAddr: address})
		udp := header.UDP(ip.Payload())
		udp.Encode(&header.UDPFields{SrcPort: 50000, DstPort: 443, Length: uint16(header.UDPMinimumSize + len(payload))})
		copy(udp.Payload(), payload)
		require.NoError(t, port.WritePackets([][]byte{packet}))
		select {
		case reply := <-returnPath.packets:
			replyIP := header.IPv4(reply)
			require.Equal(t, address, replyIP.SourceAddr())
			require.Equal(t, internal, replyIP.DestinationAddr())
			replyUDP := header.UDP(replyIP.Payload())
			require.Equal(t, uint16(50000), replyUDP.DestinationPort())
			require.Equal(t, payload, replyUDP.Payload())
		case <-time.After(5 * time.Second):
			t.Fatal("VLESS XUDP over gRPC did not return the UDP reply")
		}
	}
	require.Equal(t, int32(1), handler.calls.Load(), "destinations must share one live stream")
}
