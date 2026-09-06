package udpflow

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-snell/snellv6"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

const testTimeout = 5 * time.Second

type testFlowHandler struct {
	tun.Handler
	ports map[netip.Addr]tun.Port
	real  netip.AddrPort
}

func (h *testFlowHandler) JudgeFlow(_ uint8, _, destination netip.AddrPort, _ []byte) tun.FlowVerdict {
	return tun.FlowVerdict{Action: tun.ActionFlow, Port: h.ports[destination.Addr()], Destination: h.real}
}

type testWriteback struct {
	packets chan []byte
}

func newTestWriteback() *testWriteback {
	return &testWriteback{packets: make(chan []byte, 16)}
}

func (w *testWriteback) ReturnHeadroom() int { return 8 }

func (w *testWriteback) WriteReturnPackets(packets [][]byte) error {
	for _, packet := range packets {
		w.packets <- append([]byte(nil), packet[w.ReturnHeadroom():]...)
	}
	return nil
}

type testDatagram struct {
	payload []byte
	address M.Socksaddr
}

type channelPacketConn struct {
	*testPacketConn
	sent     chan testDatagram
	received chan testDatagram
}

func newChannelPacketConn() *channelPacketConn {
	return &channelPacketConn{
		testPacketConn: newTestPacketConn(0),
		sent:           make(chan testDatagram, 16),
		received:       make(chan testDatagram, 16),
	}
}

func (c *channelPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	packet := testDatagram{append([]byte(nil), buffer.Bytes()...), destination}
	select {
	case c.sent <- packet:
		return nil
	case <-c.closed:
		return net.ErrClosed
	}
}

func (c *channelPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	select {
	case packet := <-c.received:
		_, err := buffer.Write(packet.payload)
		return packet.address, err
	case <-c.closed:
		return M.Socksaddr{}, net.ErrClosed
	}
}

func receiveTestValue[T any](t *testing.T, channel <-chan T) T {
	t.Helper()
	select {
	case value := <-channel:
		return value
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for test event")
		var zero T
		return zero
	}
}

func newChannelPort(t *testing.T, conn *channelPacketConn) *Port {
	t.Helper()
	port, err := New(Options{DialPacketConn: func(context.Context, M.Socksaddr) (N.NetPacketConn, error) {
		return conn, nil
	}})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, port.Close()) })
	return port
}

// Both outbounds allocate the same selector for the same real server. Their
// synthetic port addresses must distinguish reverse mappings, including when
// two different Fake-IPs resolve to that server.
func TestDispatcherSeparatesOutbounds(t *testing.T) {
	for _, test := range []struct {
		name, client, fakeA, fakeB, real string
	}{
		{"IPv4", "192.0.2.1", "198.18.0.1", "198.18.0.2", "203.0.113.10:443"},
		{"IPv6", "2001:db8::1", "fc00::1", "fc00::2", "[2001:db8::10]:443"},
	} {
		t.Run(test.name, func(t *testing.T) {
			connA, connB := newChannelPacketConn(), newChannelPacketConn()
			portA, portB := newChannelPort(t, connA), newChannelPort(t, connB)
			fakeA, fakeB := netip.MustParseAddr(test.fakeA), netip.MustParseAddr(test.fakeB)
			client, real := netip.MustParseAddr(test.client), netip.MustParseAddrPort(test.real)
			writeback := newTestWriteback()
			handler := &testFlowHandler{ports: map[netip.Addr]tun.Port{fakeA: portA, fakeB: portB}, real: real}
			dispatcher := tun.NewForwardDispatcher(handler, writeback, logger.NOP(), time.Minute, time.Minute)
			t.Cleanup(dispatcher.Close)
			for _, fake := range []netip.Addr{fakeA, fakeB} {
				packet := buildTestUDPPacket(t, client, 50000, fake, 443, []byte("query"))
				require.True(t, dispatcher.Dispatch(packet))
			}
			dispatcher.Flush()
			for index, conn := range []*channelPacketConn{connA, connB} {
				request := receiveTestValue(t, conn.sent)
				require.Equal(t, M.SocksaddrFromNetIP(real), request.address)
				require.Equal(t, []byte("query"), request.payload)
				reply := []byte{byte(index)}
				conn.received <- testDatagram{reply, M.SocksaddrFromNetIP(real)}
				source, destination, payload, ok := parseUDPPacket(receiveTestValue(t, writeback.packets))
				require.True(t, ok)
				require.Equal(t, netip.AddrPortFrom([]netip.Addr{fakeA, fakeB}[index], 443), source)
				require.Equal(t, netip.AddrPortFrom(client, 50000), destination)
				require.Equal(t, reply, payload)
			}
		})
	}
}

// A second dispatcher must fall back to the normal packet path, since its
// independently allocated selectors cannot safely share the first association.
func TestDispatcherRejectsSecondInbound(t *testing.T) {
	conn := newChannelPacketConn()
	port := newChannelPort(t, conn)
	fake := netip.MustParseAddr("198.18.0.1")
	real := netip.MustParseAddrPort("203.0.113.10:443")
	handler := &testFlowHandler{ports: map[netip.Addr]tun.Port{fake: port}, real: real}
	writebackA, writebackB := newTestWriteback(), newTestWriteback()
	dispatcherA := tun.NewForwardDispatcher(handler, writebackA, logger.NOP(), time.Minute, time.Minute)
	dispatcherB := tun.NewForwardDispatcher(handler, writebackB, logger.NOP(), time.Minute, time.Minute)
	t.Cleanup(dispatcherA.Close)
	t.Cleanup(dispatcherB.Close)
	clientA := netip.MustParseAddr("192.0.2.1")
	packetA := buildTestUDPPacket(t, clientA, 50000, fake, 443, []byte("a"))
	packetB := buildTestUDPPacket(t, netip.MustParseAddr("192.0.2.2"), 50000, fake, 443, []byte("b"))
	require.True(t, dispatcherA.Dispatch(packetA))
	dispatcherA.Flush()
	require.False(t, dispatcherB.Dispatch(packetB), "the second inbound must use the legacy path")
	dispatcherB.Flush()
	require.Equal(t, []byte("a"), receiveTestValue(t, conn.sent).payload)
	conn.received <- testDatagram{[]byte("reply"), M.SocksaddrFromNetIP(real)}
	_, destination, _, ok := parseUDPPacket(receiveTestValue(t, writebackA.packets))
	require.True(t, ok)
	require.Equal(t, netip.AddrPortFrom(clientA, 50000), destination)
	require.Empty(t, writebackB.packets)
}

type observedConn struct {
	net.Conn
	once  sync.Once
	wrote chan struct{}
}

func (c *observedConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.once.Do(func() { close(c.wrote) })
	}
	return n, err
}

// Snell v6 reads the server's handshake reply inside WritePacket. A silent
// server used to block Flush, and therefore all subsequent TUN reads.
func TestDispatcherDoesNotWaitForSnellHandshake(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	observed := &observedConn{Conn: clientConn, wrote: make(chan struct{})}
	go io.Copy(io.Discard, serverConn)
	client, err := snellv6.NewClient(snellv6.ClientOptions{PSK: []byte("udp-flow-test"), Mode: snellv6.ModeUnshaped})
	require.NoError(t, err)
	port, err := New(Options{WriteTimeout: testTimeout, DialPacketConn: func(context.Context, M.Socksaddr) (N.NetPacketConn, error) {
		return client.DialPacketConn(observed)
	}})
	require.NoError(t, err)
	defer port.Close()
	fake := netip.MustParseAddr("198.18.0.1")
	handler := &testFlowHandler{ports: map[netip.Addr]tun.Port{fake: port}, real: netip.MustParseAddrPort("203.0.113.10:443")}
	dispatcher := tun.NewForwardDispatcher(handler, newTestWriteback(), logger.NOP(), time.Minute, time.Minute)
	defer dispatcher.Close()
	packet := buildTestUDPPacket(t, netip.MustParseAddr("192.0.2.1"), 50000, fake, 443, []byte("query"))
	require.True(t, dispatcher.Dispatch(packet))
	done := make(chan struct{})
	go func() { dispatcher.Flush(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		clientConn.Close()
		receiveTestValue(t, done)
		t.Fatal("Flush waited for the Snell handshake")
	}
	receiveTestValue(t, observed.wrote)
	closeDone := make(chan struct{})
	go func() { port.Close(); close(closeDone) }()
	receiveTestValue(t, closeDone)
}
