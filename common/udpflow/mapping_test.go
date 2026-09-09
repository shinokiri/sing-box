package udpflow

import (
	"context"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

func newMappingTestPort(t *testing.T) (*Port, chan *channelPacketConn) {
	t.Helper()
	created := make(chan *channelPacketConn, 16)
	port, err := New(Options{DialPacketConn: func(context.Context, M.Socksaddr) (N.NetPacketConn, error) {
		conn := newChannelPacketConn()
		created <- conn
		return conn, nil
	}})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, port.Close()) })
	return port, created
}

func TestDispatcherUDPCollisionFollowup(t *testing.T) {
	for _, test := range []struct{ name, a, b, fakeA, fakeB, real string }{
		{"IPv4/clients", "192.0.2.1", "192.0.2.2", "198.18.0.1", "198.18.0.1", "203.0.113.1"},
		{"IPv6/clients", "2001:db8::1", "2001:db8::2", "fc00::1", "fc00::1", "2001:db8::10"},
		{"IPv4/aliases", "192.0.2.1", "192.0.2.1", "198.18.0.1", "198.18.0.2", "203.0.113.1"},
		{"IPv6/aliases", "2001:db8::1", "2001:db8::1", "fc00::1", "fc00::2", "2001:db8::10"},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				port, created := newMappingTestPort(t)
				real := netip.MustParseAddr(test.real)
				w := newTestWriteback()
				d := tun.NewForwardDispatcher(&replyFlowHandler{port: port, real: real}, w, logger.NOP(), time.Minute, time.Minute)
				defer d.Close()
				send := func(client, fake string, target uint16) {
					require.True(t, d.Dispatch(buildTestUDPPacket(t, netip.MustParseAddr(client), 50000, netip.MustParseAddr(fake), target, []byte("request"))))
					d.Flush()
				}
				send(test.a, test.fakeA, 69)
				first := receiveTestValue(t, created)
				receiveTestValue(t, first.sent)
				send(test.b, test.fakeB, 69)
				second := receiveTestValue(t, created)
				receiveTestValue(t, second.sent)
				second.received <- testDatagram{[]byte("offer"), M.SocksaddrFromNetIP(netip.AddrPortFrom(real, 40000))}
				source, dest, _, ok := parseUDPPacket(receiveTestValue(t, w.packets))
				require.True(t, ok)
				require.Equal(t, netip.AddrPortFrom(netip.MustParseAddr(test.fakeB), 40000), source)
				require.Equal(t, netip.AddrPortFrom(netip.MustParseAddr(test.b), 50000), dest)
				send(test.b, test.fakeB, 40000)
				synctest.Wait()
				require.Empty(t, created, "follow-up must stay on the association that received the offer")
				require.Equal(t, uint16(40000), receiveTestValue(t, second.sent).address.Port)
			})
		})
	}
}

func TestDispatcherUDPMappingLifetime(t *testing.T) {
	for _, mode := range []string{"idle-timeout", "route-change", "alias-timeout"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				port, created := newMappingTestPort(t)
				lifetime, cancel := context.WithCancel(context.Background())
				defer cancel()
				oldReal, newReal := netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("203.0.113.2")
				fake := netip.MustParseAddr("198.18.0.1")
				newClient, newFake := "192.0.2.2", fake
				if mode == "alias-timeout" {
					newClient, newReal = "192.0.2.1", oldReal
					newFake = netip.MustParseAddr("198.18.0.2")
				}
				h := &replyFlowHandler{port: port, real: oldReal, lifetime: lifetime}
				timeout := 10 * time.Second
				if mode == "route-change" {
					timeout = 5 * time.Minute
				}
				w := newTestWriteback()
				d := tun.NewForwardDispatcher(h, w, logger.NOP(), timeout, time.Minute)
				defer d.Close()
				send := func(client string, target netip.Addr) {
					require.True(t, d.Dispatch(buildTestUDPPacket(t, netip.MustParseAddr(client), 50000, target, 69, []byte("request"))))
					d.Flush()
				}
				send("192.0.2.1", fake)
				oldConn := receiveTestValue(t, created)
				receiveTestValue(t, oldConn.sent)
				if mode == "route-change" {
					cancel()
				}
				time.Sleep(31 * time.Second)
				d.Flush()
				h.real, h.lifetime = newReal, nil
				send(newClient, newFake)
				synctest.Wait()
				oldConn.received <- testDatagram{[]byte("old reply"), M.SocksaddrFromNetIP(netip.AddrPortFrom(oldReal, 69))}
				synctest.Wait()
				require.Empty(t, w.packets, "a retired association must not send replies through its successor's mapping")
				require.Len(t, created, 1, "a different owner needs a fresh association")
				current := <-created
				receiveTestValue(t, current.sent)
				receiveTestValue(t, oldConn.closed)
				current.received <- testDatagram{[]byte("current"), M.SocksaddrFromNetIP(netip.AddrPortFrom(newReal, 69))}
				source, dest, payload, ok := parseUDPPacket(receiveTestValue(t, w.packets))
				require.True(t, ok)
				require.Equal(t, "current", string(payload))
				require.Equal(t, netip.AddrPortFrom(newFake, 69), source)
				require.Equal(t, netip.AddrPortFrom(netip.MustParseAddr(newClient), 50000), dest)
			})
		})
	}
}

func TestDispatcherUDPExpiredRouteDoesNotRenewAssociation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		conn := newChannelPacketConn()
		port := newChannelPort(t, conn)
		lifetime, cancel := context.WithCancel(context.Background())
		defer cancel()
		real, fake := netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("198.18.0.1")
		w := newTestWriteback()
		d := tun.NewForwardDispatcher(&replyFlowHandler{port: port, real: real, lifetime: lifetime}, w, logger.NOP(), 5*time.Minute, time.Minute)
		defer d.Close()
		require.True(t, d.Dispatch(buildTestUDPPacket(t, netip.MustParseAddr("192.0.2.1"), 50000, fake, 69, []byte("request"))))
		d.Flush()
		receiveTestValue(t, conn.sent)
		cancel()
		// No more TUN sends or Flush calls: the port's existing sweeper must
		// release a connection whose routes have all expired, even with replies.
		for range 12 {
			time.Sleep(time.Minute)
			conn.received <- testDatagram{[]byte("stale"), M.SocksaddrFromNetIP(netip.AddrPortFrom(real, 69))}
			synctest.Wait()
		}
		require.Empty(t, w.packets)
		require.Empty(t, port.flows)
		receiveTestValue(t, conn.closed)
	})
}

func TestDispatcherUDPSharedMappingRetainsPeerOwnership(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		port, created := newMappingTestPort(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		a, b := netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("203.0.113.2")
		h := &replyFlowHandler{port: port, real: a, lifetime: ctx}
		w := newTestWriteback()
		d := tun.NewForwardDispatcher(h, w, logger.NOP(), 5*time.Minute, time.Minute)
		defer d.Close()
		send := func(fake string) {
			require.True(t, d.Dispatch(buildTestUDPPacket(t, netip.MustParseAddr("192.0.2.1"), 50000, netip.MustParseAddr(fake), 69, []byte("request"))))
			d.Flush()
		}
		send("198.18.0.1")
		shared := receiveTestValue(t, created)
		receiveTestValue(t, shared.sent)
		h.real, h.lifetime = b, nil
		send("198.18.0.2")
		receiveTestValue(t, shared.sent)
		cancel()
		time.Sleep(31 * time.Second)
		d.Flush()
		synctest.Wait()
		require.Empty(t, created)
		shared.received <- testDatagram{[]byte("retired peer"), M.SocksaddrFromNetIP(netip.AddrPortFrom(a, 40000))}
		synctest.Wait()
		require.Empty(t, w.packets, "a retired peer must not become an unknown peer on the surviving socket")
		shared.received <- testDatagram{[]byte("healthy"), M.SocksaddrFromNetIP(netip.AddrPortFrom(b, 69))}
		_, _, payload, ok := parseUDPPacket(receiveTestValue(t, w.packets))
		require.True(t, ok)
		require.Equal(t, "healthy", string(payload))
		h.real = a
		send("198.18.0.3")
		replacement := receiveTestValue(t, created)
		receiveTestValue(t, replacement.sent)
		replacement.received <- testDatagram{[]byte("new alias"), M.SocksaddrFromNetIP(netip.AddrPortFrom(a, 40000))}
		source, _, _, ok := parseUDPPacket(receiveTestValue(t, w.packets))
		require.True(t, ok)
		require.Equal(t, netip.MustParseAddrPort("198.18.0.3:40000"), source)
		select {
		case <-shared.closed:
			t.Fatal("unaffected peer lost its shared association")
		default:
		}
	})
}

func TestDispatcherUDPFamiliesHaveSeparateLifetimes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		port, created := newMappingTestPort(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		h := &replyFlowHandler{port: port, lifetime: ctx}
		w := newTestWriteback()
		d := tun.NewForwardDispatcher(h, w, logger.NOP(), 5*time.Minute, time.Minute)
		defer d.Close()
		var conns []*channelPacketConn
		for _, endpoints := range []struct{ client, fake, real string }{
			{"192.0.2.1", "198.18.0.1", "203.0.113.1"},
			{"2001:db8::1", "fc00::1", "2001:db8::10"},
		} {
			h.real = netip.MustParseAddr(endpoints.real)
			require.True(t, d.Dispatch(buildTestUDPPacket(t, netip.MustParseAddr(endpoints.client), 50000, netip.MustParseAddr(endpoints.fake), 69, []byte("request"))))
			d.Flush()
			synctest.Wait()
			require.Len(t, created, 1, "equal port numbers in different IP families do not identify one client socket")
			conn := <-created
			conns = append(conns, conn)
			receiveTestValue(t, conn.sent)
			h.lifetime = nil
		}
		cancel()
		time.Sleep(31 * time.Second)
		d.Flush()
		synctest.Wait()
		receiveTestValue(t, conns[0].closed)
		conns[1].received <- testDatagram{[]byte("IPv6 survives"), M.ParseSocksaddr("[2001:db8::10]:40000")}
		_, dest, payload, ok := parseUDPPacket(receiveTestValue(t, w.packets))
		require.True(t, ok)
		require.Equal(t, "IPv6 survives", string(payload))
		require.Equal(t, netip.MustParseAddrPort("[2001:db8::1]:50000"), dest)
	})
}
