package udpflow

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/snellv4"
	"github.com/sagernet/sing-snell/snellv5"
	"github.com/sagernet/sing-snell/snellv6"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

type echoPacketHandler struct {
	N.TCPConnectionHandlerEx
	packets chan testDatagram
}

func (h *echoPacketHandler) NewPacketConnectionEx(_ context.Context, conn N.PacketConn, _, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	go func() {
		defer conn.Close()
		for {
			buffer := buf.NewSize(65535)
			destination, err := conn.ReadPacket(buffer)
			if err != nil {
				buffer.Release()
				return
			}
			h.packets <- testDatagram{append([]byte(nil), buffer.Bytes()...), destination}
			if _, err = bufio.WritePacketBuffer(conn, buffer, destination); err != nil {
				return
			}
		}
	}()
}

// Exercise the actual framing, changing headroom, and multi-destination replies
// with in-process protocol servers, without requiring a privileged TUN device.
func TestPortProtocolRoundTrip(t *testing.T) {
	for _, protocol := range []string{"snell-v4", "snell-v4-http", "snell-v6", "snell-v6-unshaped", "snell-v6-unsafe-raw", "vless-xudp"} {
		t.Run(protocol, func(t *testing.T) {
			handler := &echoPacketHandler{packets: make(chan testDatagram, 8)}
			dial := newProtocolTestDialer(t, protocol, handler)
			var calls atomic.Int32
			port, err := New(Options{DialPacketConn: func(ctx context.Context, destination M.Socksaddr) (N.NetPacketConn, error) {
				calls.Add(1)
				return dial(ctx, destination)
			}})
			require.NoError(t, err)
			defer port.Close()
			returnPath := newTestReturn()
			require.NoError(t, port.AttachReturn(returnPath))
			inet4, inet6 := port.PortAddresses()
			for index, address := range []string{"203.0.113.1:443", "[2001:db8::1]:53", "203.0.113.2:3478"} {
				destination := netip.MustParseAddrPort(address)
				internalAddress := inet4
				if destination.Addr().Is6() {
					internalAddress = inet6
				}
				payload := []byte{byte(index), 1, 2, 3}
				packet := buildTestUDPPacket(t, internalAddress, 50000, destination.Addr(), destination.Port(), payload)
				require.NoError(t, port.WritePackets([][]byte{packet}))
				request := receiveTestValue(t, handler.packets)
				require.Equal(t, payload, request.payload)
				require.Equal(t, M.SocksaddrFromNetIP(destination), request.address)
				source, target, reply, ok := parseUDPPacket(receiveTestValue(t, returnPath.packets))
				require.True(t, ok)
				require.Equal(t, destination, source)
				require.Equal(t, netip.AddrPortFrom(internalAddress, 50000), target)
				require.Equal(t, payload, reply)
			}
			require.Equal(t, int32(1), calls.Load(), "all destinations must share one association")
		})
	}
}

func newProtocolTestDialer(t *testing.T, protocol string, handler interface {
	N.TCPConnectionHandlerEx
	N.UDPConnectionHandlerEx
}) PacketConnFactory {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { clientConn.Close() })
	t.Cleanup(func() { serverConn.Close() })
	var dial PacketConnFactory
	var serve func() error
	switch protocol {
	case "vless-xudp":
		const user = "b831381d-6324-4d53-ad4f-8cda48b30811"
		client, err := vless.NewClient(user, "", logger.NOP())
		require.NoError(t, err)
		server := vless.NewService[string](logger.NOP(), handler)
		server.UpdateUsers([]string{"test"}, []string{user}, []string{""})
		dial = func(ctx context.Context, destination M.Socksaddr) (N.NetPacketConn, error) {
			stop := context.AfterFunc(ctx, func() { clientConn.Close() })
			defer stop()
			return client.DialEarlyXUDPPacketConn(clientConn, destination)
		}
		serve = func() error { return server.NewConnection(context.Background(), serverConn, M.Socksaddr{}, nil) }
	case "snell-v4", "snell-v4-http":
		mode := snell.ObfsModeNone
		if protocol == "snell-v4-http" {
			mode = snell.ObfsModeHTTP
		}
		psk := []byte("udp-flow-test-key")
		client, err := snellv4.NewClient(snellv4.ClientOptions{PSK: psk, ObfsMode: mode, ObfsHost: "example.com"})
		require.NoError(t, err)
		server, err := snellv5.NewService(snellv5.ServiceOptions{PSK: psk, ObfsMode: mode, Handler: handler})
		require.NoError(t, err)
		dial = func(context.Context, M.Socksaddr) (N.NetPacketConn, error) { return client.DialPacketConn(clientConn) }
		serve = func() error { return server.NewConnection(context.Background(), serverConn, M.Socksaddr{}, nil) }
	default:
		mode := snellv6.ModeDefault
		if protocol == "snell-v6-unshaped" {
			mode = snellv6.ModeUnshaped
		} else if protocol == "snell-v6-unsafe-raw" {
			mode = snellv6.ModeUnsafeRaw
		}
		psk := []byte("udp-flow-test-key")
		client, err := snellv6.NewClient(snellv6.ClientOptions{PSK: psk, Mode: mode})
		require.NoError(t, err)
		server, err := snellv6.NewService(snellv6.ServerOptions{PSK: psk, Mode: mode, Handler: handler})
		require.NoError(t, err)
		dial = func(context.Context, M.Socksaddr) (N.NetPacketConn, error) { return client.DialPacketConn(clientConn) }
		serve = func() error { return server.NewConnection(context.Background(), serverConn, M.Socksaddr{}, nil) }
	}
	go func() {
		if err := serve(); err != nil {
			serverConn.Close()
		}
	}()
	return dial
}
