package udpflow

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

func TestPortReusesSelectorAcrossDestinations(t *testing.T) {
	var factoryCalls atomic.Int32
	packetConn := newTestPacketConn(16)
	port, err := New(Options{
		Context: context.Background(),
		Name:    "test",
		DialPacketConn: func(_ context.Context, firstDestination M.Socksaddr) (N.NetPacketConn, error) {
			factoryCalls.Add(1)
			packetConn.firstDestination = firstDestination
			return packetConn, nil
		},
	})
	require.NoError(t, err)
	defer port.Close()

	packetA := buildTestUDPPacket(t, netip.MustParseAddr("0.0.0.0"), 50000, netip.MustParseAddr("1.1.1.1"), 3478, []byte("a"))
	packetB := buildTestUDPPacket(t, netip.MustParseAddr("0.0.0.0"), 50000, netip.MustParseAddr("8.8.8.8"), 53, []byte("b"))
	require.NoError(t, port.WritePackets([][]byte{packetA, packetB}))
	require.Eventually(t, func() bool { return len(packetConn.destinations()) == 2 }, time.Second, time.Millisecond)
	require.Equal(t, int32(1), factoryCalls.Load())
	require.Equal(t, M.SocksaddrFromNetIP(netip.MustParseAddrPort("1.1.1.1:3478")), packetConn.firstDestination)
	require.Equal(t, []M.Socksaddr{
		M.SocksaddrFromNetIP(netip.MustParseAddrPort("1.1.1.1:3478")),
		M.SocksaddrFromNetIP(netip.MustParseAddrPort("8.8.8.8:53")),
	}, packetConn.destinations())
}

func TestPortCreatesSeparateSelectors(t *testing.T) {
	var factoryCalls atomic.Int32
	port, err := New(Options{
		Context: context.Background(),
		Name:    "test",
		DialPacketConn: func(_ context.Context, _ M.Socksaddr) (N.NetPacketConn, error) {
			factoryCalls.Add(1)
			return newTestPacketConn(0), nil
		},
	})
	require.NoError(t, err)
	defer port.Close()

	packetA := buildTestUDPPacket(t, netip.MustParseAddr("0.0.0.0"), 50000, netip.MustParseAddr("1.1.1.1"), 3478, []byte("a"))
	packetB := buildTestUDPPacket(t, netip.MustParseAddr("0.0.0.0"), 50001, netip.MustParseAddr("8.8.8.8"), 53, []byte("b"))
	require.NoError(t, port.WritePackets([][]byte{packetA, packetB}))
	require.Eventually(t, func() bool { return factoryCalls.Load() == 2 }, time.Second, time.Millisecond)
}

// TestPortPreservesRearHeadroom covers the regression that previously caused
// Snell v6 to panic while appending its 16-byte authentication tag.
func TestPortPreservesRearHeadroom(t *testing.T) {
	packetConn := newTestPacketConn(16)
	port, err := New(Options{
		Context: context.Background(),
		Name:    "test",
		DialPacketConn: func(_ context.Context, _ M.Socksaddr) (N.NetPacketConn, error) {
			return packetConn, nil
		},
	})
	require.NoError(t, err)
	defer port.Close()

	packet := buildTestUDPPacket(t, netip.MustParseAddr("0.0.0.0"), 50000, netip.MustParseAddr("1.1.1.1"), 3478, []byte("payload"))
	require.NoError(t, port.WritePackets([][]byte{packet}))
	require.Eventually(t, func() bool { return len(packetConn.destinations()) == 1 }, time.Second, time.Millisecond)
	require.False(t, packetConn.headroomViolation.Load())
}

type framingPacketConn struct {
	*testPacketConn
	frame int // accessed only by the packet writer and its headroom methods
	sent  chan testDatagram
}

var testFraming = [][2]int{{64, 16}, {512, 32}, {8, 0}, {128, 16}}

func (c *framingPacketConn) FrontHeadroom() int { return testFraming[c.frame][0] }
func (c *framingPacketConn) RearHeadroom() int  { return testFraming[c.frame][1] }

func (c *framingPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	front, rear := c.FrontHeadroom(), c.RearHeadroom()
	if buffer.Start() < front || buffer.FreeLen() < rear {
		return io.ErrShortBuffer
	}
	packet := testDatagram{append([]byte(nil), buffer.Bytes()...), destination}
	clear(buffer.ExtendHeader(front))
	clear(buffer.Extend(rear))
	if c.frame < len(testFraming)-1 {
		c.frame++
	}
	c.sent <- packet
	return nil
}

// Packets queued before a dial completes have no framing reservation. Later
// requirements may grow or shrink, and enqueue must not inspect writer state.
func TestPortHandlesChangingHeadroom(t *testing.T) {
	conn := &framingPacketConn{testPacketConn: newTestPacketConn(0), sent: make(chan testDatagram, 8)}
	release := make(chan struct{})
	port, err := New(Options{DialPacketConn: func(ctx context.Context, _ M.Socksaddr) (N.NetPacketConn, error) {
		select {
		case <-release:
			return conn, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}})
	require.NoError(t, err)
	defer port.Close()
	for _, payload := range []string{"first", "larger header", "", "smaller header"} {
		require.NoError(t, port.WritePackets([][]byte{testPortPacket(t, 50000, payload)}))
	}
	close(release)
	for _, payload := range []string{"first", "larger header", "", "smaller header"} {
		require.Equal(t, payload, string(receiveTestValue(t, conn.sent).payload))
	}
	// Steady traffic uses the reservation published by the worker.
	for range 32 {
		require.NoError(t, port.WritePackets([][]byte{testPortPacket(t, 50000, "established")}))
		require.Equal(t, "established", string(receiveTestValue(t, conn.sent).payload))
	}
}

type testPacketConn struct {
	rearHeadroom     int
	firstDestination M.Socksaddr

	access            sync.Mutex
	written           []M.Socksaddr
	closed            chan struct{}
	closeOnce         sync.Once
	headroomViolation atomic.Bool
}

func newTestPacketConn(rearHeadroom int) *testPacketConn {
	return &testPacketConn{rearHeadroom: rearHeadroom, closed: make(chan struct{})}
}

func (c *testPacketConn) RearHeadroom() int {
	return c.rearHeadroom
}

func (c *testPacketConn) ReadPacket(_ *buf.Buffer) (M.Socksaddr, error) {
	<-c.closed
	return M.Socksaddr{}, io.EOF
}

func (c *testPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	if buffer.FreeLen() < c.rearHeadroom {
		c.headroomViolation.Store(true)
		return io.ErrShortBuffer
	}
	if c.rearHeadroom > 0 {
		buffer.Extend(c.rearHeadroom)
	}
	c.access.Lock()
	c.written = append(c.written, destination)
	c.access.Unlock()
	return nil
}

func (c *testPacketConn) destinations() []M.Socksaddr {
	c.access.Lock()
	defer c.access.Unlock()
	return append([]M.Socksaddr(nil), c.written...)
}

func (c *testPacketConn) ReadFrom(_ []byte) (int, net.Addr, error) {
	<-c.closed
	return 0, nil, io.EOF
}

func (c *testPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return len(p), nil
}

func (c *testPacketConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *testPacketConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (c *testPacketConn) SetDeadline(_ time.Time) error      { return nil }
func (c *testPacketConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *testPacketConn) SetWriteDeadline(_ time.Time) error { return nil }
