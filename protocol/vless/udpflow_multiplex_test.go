package vless

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type flowMultiplexRouter struct {
	adapter.Router
	tcpStreams atomic.Int32
}

func (r *flowMultiplexRouter) RouteConnectionEx(_ context.Context, conn net.Conn, _ adapter.InboundContext, _ N.CloseHandlerFunc) {
	r.tcpStreams.Add(1)
	go func() {
		defer conn.Close()
		io.Copy(conn, conn)
	}()
}

func (*flowMultiplexRouter) RoutePacketConnectionEx(_ context.Context, conn N.PacketConn, _ adapter.InboundContext, _ N.CloseHandlerFunc) {
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

func TestXUDPFlowWithTCPMultiplex(t *testing.T) {
	for _, protocol := range []string{"smux", "yamux", "h2mux"} {
		t.Run(protocol, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			const user = "b831381d-6324-4d53-ad4f-8cda48b30811"
			router := &flowMultiplexRouter{}
			inboundRaw, err := NewInbound(ctx, router, logger.NOP(), "server", option.VLESSInboundOptions{
				Users: []option.VLESSUser{{UUID: user}}, Multiplex: &option.InboundMultiplexOptions{Enabled: true},
			})
			require.NoError(t, err)
			inbound := inboundRaw.(*Inbound)
			defer inbound.Close()
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer listener.Close()
			var connections atomic.Int32
			go func() {
				for {
					conn, acceptErr := listener.Accept()
					if acceptErr != nil {
						return
					}
					connections.Add(1)
					go inbound.NewConnection(ctx, conn, adapter.InboundContext{}, nil)
				}
			}()
			server := M.SocksaddrFromNet(listener.Addr())
			outboundRaw, err := NewOutbound(ctx, nil, logger.NOP(), "client", option.VLESSOutboundOptions{
				ServerOptions: option.ServerOptions{Server: server.Addr.String(), ServerPort: server.Port},
				UUID:          user, UDPFlow: true,
				Multiplex: &option.OutboundMultiplexOptions{Enabled: true, Protocol: protocol, MaxConnections: 1},
			})
			require.NoError(t, err)
			outbound := outboundRaw.(*Outbound)
			defer outbound.Close()
			destination := M.ParseSocksaddr("203.0.113.1:443")
			var streams []net.Conn
			ping := func(conn net.Conn) {
				t.Helper()
				_, err := conn.Write([]byte("ping"))
				require.NoError(t, err)
				reply := make([]byte, 4)
				_, err = io.ReadFull(conn, reply)
				require.NoError(t, err)
				require.Equal(t, "ping", string(reply))
			}
			for range 2 {
				conn, err := outbound.DialContext(ctx, N.NetworkTCP, destination)
				require.NoError(t, err)
				defer conn.Close()
				stop := context.AfterFunc(ctx, func() { conn.Close() })
				defer stop()
				streams = append(streams, conn)
				ping(conn)
			}
			require.Equal(t, int32(1), connections.Load(), "TCP streams must share the multiplex connection")
			require.Equal(t, int32(2), router.tcpStreams.Load())
			returnPath := &flowTransportReturn{packets: make(chan []byte, 1)}
			require.NoError(t, outbound.AttachReturn(returnPath))
			internal, _ := outbound.PortAddresses()
			packet := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize+4)
			ip := header.IPv4(packet)
			ip.Encode(&header.IPv4Fields{TotalLength: uint16(len(packet)), TTL: 64, Protocol: uint8(header.UDPProtocolNumber), SrcAddr: internal, DstAddr: destination.Addr})
			udp := header.UDP(ip.Payload())
			udp.Encode(&header.UDPFields{SrcPort: 50000, DstPort: destination.Port, Length: header.UDPMinimumSize + 4})
			copy(udp.Payload(), "flow")
			require.NoError(t, outbound.WritePackets([][]byte{packet}))
			select {
			case reply := <-returnPath.packets:
				require.Equal(t, "flow", string(header.UDP(header.IPv4(reply).Payload()).Payload()))
			case <-ctx.Done():
				t.Fatal("UDP flow did not coexist with TCP multiplex")
			}
			require.Equal(t, int32(2), connections.Load(), "UDP flow must use its own XUDP association")
			outbound.flowPort.Reset()
			for _, conn := range streams {
				ping(conn)
			}
			require.Equal(t, int32(2), connections.Load(), "resetting UDP flow must keep TCP multiplex alive")
		})
	}
}
