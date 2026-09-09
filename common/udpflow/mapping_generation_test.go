package udpflow

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

type slowCloseMappingConn struct {
	*channelPacketConn
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *slowCloseMappingConn) Close() error {
	c.once.Do(func() { close(c.started) })
	<-c.release
	return c.channelPacketConn.Close()
}

func TestDispatcherUDPRetiredReturnCannotUseRecycledSelector(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		oldConn := &slowCloseMappingConn{channelPacketConn: newChannelPacketConn(), started: make(chan struct{}), release: make(chan struct{})}
		currentConn := newChannelPacketConn()
		calls := 0
		port, err := New(Options{DialPacketConn: func(context.Context, M.Socksaddr) (N.NetPacketConn, error) {
			calls++
			if calls == 1 {
				return oldConn, nil
			}
			return currentConn, nil
		}})
		require.NoError(t, err)
		defer port.Close()
		defer close(oldConn.release)
		real := netip.MustParseAddr("203.0.113.1")
		w := newTestWriteback()
		d := tun.NewForwardDispatcher(&replyFlowHandler{port: port, real: real}, w, logger.NOP(), 10*time.Second, time.Minute)
		defer d.Close()
		send := func(client string) {
			require.True(t, d.Dispatch(buildTestUDPPacket(t, netip.MustParseAddr(client), 50000, netip.MustParseAddr("198.18.0.1"), 69, []byte("request"))))
			d.Flush()
		}
		send("192.0.2.1")
		receiveTestValue(t, oldConn.sent)
		var captured tun.UDPMapping
		var source netip.AddrPort
		port.access.Lock()
		for f := range port.flows {
			captured, source = f.mapping, f.key
		}
		port.access.Unlock()
		require.NotNil(t, captured)
		time.Sleep(31 * time.Second)
		d.Flush() // Must return even though protocol Close will block.
		receiveTestValue(t, oldConn.started)
		send("192.0.2.2")
		receiveTestValue(t, currentConn.sent)
		// Simulate a reply which was read before Close and resumed only after
		// the numeric selector acquired a different owner. Cover both paths.
		for _, endpoint := range []string{"203.0.113.1:69", "203.0.113.1:40000", "203.0.113.2:40000"} {
			raw, err := buildUDPResponse(w.ReturnHeadroom(), M.ParseSocksaddr(endpoint), source, []byte("late"))
			require.NoError(t, err)
			require.False(t, captured.ReturnPacket(raw))
		}
		require.Empty(t, w.packets)
		currentConn.received <- testDatagram{[]byte("current"), M.ParseSocksaddr("203.0.113.1:69")}
		_, dest, payload, ok := parseUDPPacket(receiveTestValue(t, w.packets))
		require.True(t, ok)
		require.Equal(t, netip.MustParseAddrPort("192.0.2.2:50000"), dest)
		require.Equal(t, "current", string(payload))
	})
}
