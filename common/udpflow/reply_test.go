package udpflow

import (
	"context"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

type alternateSourceHandler struct {
	N.TCPConnectionHandlerEx
	packets chan testDatagram
}

func (h *alternateSourceHandler) NewPacketConnectionEx(_ context.Context, conn N.PacketConn, _, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	go func() {
		defer conn.Close()
		buffer := buf.NewSize(65535)
		defer buffer.Release()
		target, err := conn.ReadPacket(buffer)
		if err != nil {
			return
		}
		h.packets <- testDatagram{append([]byte(nil), buffer.Bytes()...), target}
		alternate := target
		alternate.Port = 40000
		// The same reliable stream transports the alternative source first.
		// Receipt of "control" proves the prior packet has been processed.
		if _, err = bufio.WritePacketBuffer(conn, buf.As([]byte("alternate")), alternate); err != nil {
			return
		}
		if _, err = bufio.WritePacketBuffer(conn, buf.As([]byte("control")), target); err != nil {
			return
		}
		buffer.Resize(0, 0)
		if target, err = conn.ReadPacket(buffer); err == nil {
			h.packets <- testDatagram{append([]byte(nil), buffer.Bytes()...), target}
		}
	}()
}

func TestDispatcherProtocolAlternateSourcePort(t *testing.T) {
	for _, protocol := range []string{"snell-v4", "snell-v4-http", "snell-v6", "snell-v6-unshaped", "snell-v6-unsafe-raw", "vless-xudp"} {
		t.Run(protocol, func(t *testing.T) {
			handler := &alternateSourceHandler{packets: make(chan testDatagram, 8)}
			dial := newProtocolTestDialer(t, protocol, handler)

			port, err := New(Options{DialPacketConn: dial})
			require.NoError(t, err)
			defer port.Close()
			fake := netip.MustParseAddr("198.18.0.1")
			real := netip.MustParseAddrPort("203.0.113.1:69")
			w := newTestWriteback()
			d := tun.NewForwardDispatcher(&replyFlowHandler{port: port, real: real.Addr()}, w, logger.NOP(), time.Minute, time.Minute)
			defer d.Close()
			require.True(t, d.Dispatch(buildTestUDPPacket(t, netip.MustParseAddr("192.0.2.1"), 50000, fake, 69, []byte("request"))))
			d.Flush()
			require.Equal(t, real, receiveTestValue(t, handler.packets).address.AddrPort())
			for _, reply := range []struct {
				port    uint16
				payload string
			}{{40000, "alternate"}, {69, "control"}} {
				source, target, payload, ok := parseUDPPacket(receiveTestValue(t, w.packets))
				require.True(t, ok)
				require.Equal(t, reply.payload, string(payload))
				require.Equal(t, netip.AddrPortFrom(fake, reply.port), source)
				require.Equal(t, netip.MustParseAddrPort("192.0.2.1:50000"), target)
			}
			require.True(t, d.Dispatch(buildTestUDPPacket(t, netip.MustParseAddr("192.0.2.1"), 50000, fake, 40000, []byte("follow-up"))))
			d.Flush()
			followup := receiveTestValue(t, handler.packets)
			require.Equal(t, netip.AddrPortFrom(real.Addr(), 40000), followup.address.AddrPort())
			require.Equal(t, "follow-up", string(followup.payload))
		})
	}
}

func TestDispatcherRouteChangeDropsOldUDPReplies(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		oldConn, newConn := newChannelPacketConn(), newChannelPacketConn()
		oldPort, newPort := newChannelPort(t, oldConn), newChannelPort(t, newConn)
		lifetime, cancel := context.WithCancel(context.Background())
		defer cancel()
		real := netip.MustParseAddr("203.0.113.1")
		fake := netip.MustParseAddr("198.18.0.1")
		h := &replyFlowHandler{port: oldPort, real: real, lifetime: lifetime}
		w := newTestWriteback()
		d := tun.NewForwardDispatcher(h, w, logger.NOP(), time.Minute, time.Minute)
		defer d.Close()
		send := func() {
			require.True(t, d.Dispatch(buildTestUDPPacket(t, netip.MustParseAddr("192.0.2.1"), 50000, fake, 69, []byte("request"))))
			d.Flush()
		}
		send()
		receiveTestValue(t, oldConn.sent)
		cancel()
		for _, source := range []string{"203.0.113.1:69", "203.0.113.1:40000", "203.0.113.2:40000"} {
			oldConn.received <- testDatagram{[]byte("stale"), M.ParseSocksaddr(source)}
		}
		synctest.Wait()
		require.Empty(t, w.packets, "canceled routes must reject both exact and alternative-peer replies")
		h.port, h.lifetime = newPort, nil
		send()
		receiveTestValue(t, newConn.sent)
		newConn.received <- testDatagram{[]byte("current"), M.ParseSocksaddr("203.0.113.1:40000")}
		_, _, payload, ok := parseUDPPacket(receiveTestValue(t, w.packets))
		require.True(t, ok)
		require.Equal(t, "current", string(payload))
		d.ResetNetwork()
		newConn.received <- testDatagram{[]byte("after reset"), M.ParseSocksaddr("203.0.113.1:40000")}
		synctest.Wait()
		require.Empty(t, w.packets, "reset must discard socket reply mappings too")
	})
}

// An IP port exposes only tun.Port, without the proxy socket mapping option.
type exactReplyPort struct{ tun.Port }

func TestDispatcherIPPortKeepsExactReplyFiltering(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		conn := newChannelPacketConn()
		port := newChannelPort(t, conn)
		fake, real := netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr("203.0.113.1")
		w := newTestWriteback()
		d := tun.NewForwardDispatcher(&replyFlowHandler{port: exactReplyPort{port}, real: real}, w, logger.NOP(), time.Minute, time.Minute)
		defer d.Close()
		require.True(t, d.Dispatch(buildTestUDPPacket(t, netip.MustParseAddr("192.0.2.1"), 50000, fake, 69, []byte("request"))))
		d.Flush()
		receiveTestValue(t, conn.sent)
		conn.received <- testDatagram{[]byte("alternate"), M.ParseSocksaddr("203.0.113.1:40000")}
		conn.received <- testDatagram{[]byte("exact"), M.ParseSocksaddr("203.0.113.1:69")}
		_, _, payload, ok := parseUDPPacket(receiveTestValue(t, w.packets))
		require.True(t, ok)
		require.Equal(t, "exact", string(payload))
		synctest.Wait()
		require.Empty(t, w.packets)
	})
}

type replyFlowHandler struct {
	tun.Handler
	port     tun.Port
	real     netip.Addr
	lifetime context.Context
}

func (h *replyFlowHandler) JudgeFlow(_ uint8, _, destination netip.AddrPort, _ []byte) tun.FlowVerdict {
	v := tun.FlowVerdict{Action: tun.ActionFlow, Port: h.port, Destination: netip.AddrPortFrom(h.real, destination.Port())}
	if h.lifetime != nil {
		v.RouteContexts = []context.Context{h.lifetime}
	}
	return v
}

func TestDispatcherUDPReplyOwnership(t *testing.T) {
	for _, family := range []struct{ name, clientA, clientB, fakeA, fakeB, real, peer string }{
		{"IPv4", "192.0.2.1", "192.0.2.2", "198.18.0.1", "198.18.0.2", "203.0.113.1", "203.0.113.2"},
		{"IPv6", "2001:db8::1", "2001:db8::2", "fc00::1", "fc00::2", "2001:db8::10", "2001:db8::20"},
	} {
		for _, mode := range []string{"clients", "aliases", "shared"} {
			t.Run(family.name+"/"+mode, func(t *testing.T) {
				created := make(chan *channelPacketConn, 4)
				port, err := New(Options{DialPacketConn: func(context.Context, M.Socksaddr) (N.NetPacketConn, error) {
					conn := newChannelPacketConn()
					created <- conn
					return conn, nil
				}})
				require.NoError(t, err)
				defer port.Close()
				clients := []netip.Addr{netip.MustParseAddr(family.clientA), netip.MustParseAddr(family.clientB)}
				fakes := []netip.Addr{netip.MustParseAddr(family.fakeA), netip.MustParseAddr(family.fakeB)}
				if mode != "clients" {
					clients[1] = clients[0]
				}
				if mode != "aliases" {
					fakes[1] = fakes[0]
				}
				real := netip.MustParseAddr(family.real)
				w := newTestWriteback()
				d := tun.NewForwardDispatcher(&replyFlowHandler{port: port, real: real}, w, logger.NOP(), time.Minute, time.Minute)
				defer d.Close()
				var conns []*channelPacketConn
				for i := range 2 {
					require.True(t, d.Dispatch(buildTestUDPPacket(t, clients[i], 50000, fakes[i], uint16(69+i), []byte("request"))))
					d.Flush()
					var conn *channelPacketConn
					if mode == "shared" && i == 1 {
						conn = conns[0]
					} else {
						conn = receiveTestValue(t, created)
					}
					conns = append(conns, conn)
					require.Equal(t, netip.AddrPortFrom(real, uint16(69+i)), receiveTestValue(t, conn.sent).address.AddrPort())
				}
				for i, conn := range conns {
					conn.received <- testDatagram{[]byte("alternate"), M.SocksaddrFromNetIP(netip.AddrPortFrom(real, 40000))}
					source, dest, payload, ok := parseUDPPacket(receiveTestValue(t, w.packets))
					require.True(t, ok)
					require.Equal(t, netip.AddrPortFrom(fakes[i], 40000), source)
					require.Equal(t, netip.AddrPortFrom(clients[i], 50000), dest)
					require.Equal(t, "alternate", string(payload))
				}
				peer := netip.AddrPortFrom(netip.MustParseAddr(family.peer), 777)
				conns[0].received <- testDatagram{[]byte("new peer"), M.SocksaddrFromNetIP(peer)}
				source, dest, _, ok := parseUDPPacket(receiveTestValue(t, w.packets))
				require.True(t, ok)
				require.Equal(t, peer, source)
				require.Equal(t, netip.AddrPortFrom(clients[0], 50000), dest)
				require.Empty(t, created)
			})
		}
	}
}
