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
	require.Equal(t, int32(2), factoryCalls.Load())
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
	require.False(t, packetConn.headroomViolation.Load())
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
