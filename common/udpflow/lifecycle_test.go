package udpflow

import (
	"context"
	"errors"
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

func testPortPacket(t *testing.T, selector uint16, payload string) []byte {
	t.Helper()
	return buildTestUDPPacket(t, netip.MustParseAddr("127.0.0.1"), selector, netip.MustParseAddr("203.0.113.1"), 443, []byte(payload))
}

func TestPortCopiesQueuedPayloadAndDialsIndependently(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	connA, connB := newChannelPacketConn(), newChannelPacketConn()
	port, err := New(Options{DialPacketConn: func(ctx context.Context, destination M.Socksaddr) (N.NetPacketConn, error) {
		if destination.Port == 443 {
			close(started)
			select {
			case <-release:
				return connA, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return connB, nil
	}})
	require.NoError(t, err)
	defer port.Close()
	packetA := testPortPacket(t, 50000, "owned copy")
	require.NoError(t, port.WritePackets([][]byte{packetA}))
	receiveTestValue(t, started)
	clear(packetA)
	packetB := buildTestUDPPacket(t, netip.MustParseAddr("127.0.0.1"), 50001, netip.MustParseAddr("203.0.113.1"), 53, []byte("independent"))
	require.NoError(t, port.WritePackets([][]byte{packetB}))
	require.Equal(t, []byte("independent"), receiveTestValue(t, connB.sent).payload)
	close(release)
	require.Equal(t, []byte("owned copy"), receiveTestValue(t, connA.sent).payload)
}

func TestPortQueueLimitsAndCleanup(t *testing.T) {
	for _, test := range []struct {
		name     string
		options  Options
		selector uint16
		message  string
	}{
		{"packets", Options{QueueSize: 1}, 50000, "queue full"},
		{"bytes", Options{MaxQueuedBytes: 3}, 50000, "queue byte limit"},
		{"connections", Options{MaxFlows: 1}, 50001, "connection limit"},
	} {
		t.Run(test.name, func(t *testing.T) {
			started := make(chan struct{})
			test.options.DialPacketConn = func(ctx context.Context, _ M.Socksaddr) (N.NetPacketConn, error) {
				close(started)
				<-ctx.Done()
				return nil, ctx.Err()
			}
			port, err := New(test.options)
			require.NoError(t, err)
			defer port.Close()
			require.NoError(t, port.WritePackets([][]byte{testPortPacket(t, 50000, "ab")}))
			receiveTestValue(t, started)
			err = port.WritePackets([][]byte{testPortPacket(t, test.selector, "cd")})
			require.ErrorContains(t, err, test.message)
			require.NoError(t, port.Close())
			require.Zero(t, port.queuedBytes, "closing must release queued payloads")
			require.Empty(t, port.flows)
		})
	}
}

func TestPortCancelsPendingDial(t *testing.T) {
	for _, action := range []string{"close", "reset", "parent"} {
		t.Run(action, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			started := make(chan struct{})
			canceled := make(chan error, 1)
			var calls atomic.Int32
			conn := newChannelPacketConn()
			port, err := New(Options{Context: ctx, DialPacketConn: func(ctx context.Context, _ M.Socksaddr) (N.NetPacketConn, error) {
				if calls.Add(1) > 1 {
					return conn, nil
				}
				close(started)
				<-ctx.Done()
				canceled <- ctx.Err()
				return nil, ctx.Err()
			}})
			require.NoError(t, err)
			defer port.Close()
			packet := testPortPacket(t, 50000, "query")
			require.NoError(t, port.WritePackets([][]byte{packet}))
			receiveTestValue(t, started)
			switch action {
			case "close":
				require.NoError(t, port.Close())
			case "reset":
				port.Reset()
			case "parent":
				cancel()
			}
			require.ErrorIs(t, receiveTestValue(t, canceled), context.Canceled)
			if action == "reset" {
				require.NoError(t, port.WritePackets([][]byte{packet}))
				require.Equal(t, []byte("query"), receiveTestValue(t, conn.sent).payload)
			} else {
				require.ErrorIs(t, port.WritePackets([][]byte{packet}), net.ErrClosed)
			}
		})
	}
}

func TestPortDialTimeout(t *testing.T) {
	canceled := make(chan error, 1)
	port, err := New(Options{DialTimeout: 20 * time.Millisecond, DialPacketConn: func(ctx context.Context, _ M.Socksaddr) (N.NetPacketConn, error) {
		<-ctx.Done()
		canceled <- ctx.Err()
		return nil, ctx.Err()
	}})
	require.NoError(t, err)
	defer port.Close()
	require.NoError(t, port.WritePackets([][]byte{testPortPacket(t, 50000, "query")}))
	require.ErrorIs(t, receiveTestValue(t, canceled), context.DeadlineExceeded)
}

type blockedWritePacketConn struct {
	*testPacketConn
	started chan struct{}
}

func (c *blockedWritePacketConn) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	defer buffer.Release()
	close(c.started)
	<-c.closed
	return net.ErrClosed
}

func TestPortWriteTimeoutClosesConnection(t *testing.T) {
	conn := &blockedWritePacketConn{testPacketConn: newTestPacketConn(0), started: make(chan struct{})}
	port, err := New(Options{WriteTimeout: 20 * time.Millisecond, DialPacketConn: func(context.Context, M.Socksaddr) (N.NetPacketConn, error) {
		return conn, nil
	}})
	require.NoError(t, err)
	defer port.Close()
	require.NoError(t, port.WritePackets([][]byte{testPortPacket(t, 50000, "query")}))
	receiveTestValue(t, conn.started)
	receiveTestValue(t, conn.closed)
	require.NoError(t, port.Close())
	require.Zero(t, port.queuedBytes)
}

type failedWritePacketConn struct{ *testPacketConn }

func (c *failedWritePacketConn) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	buffer.Release()
	return errors.New("broken association")
}

func TestPortRecreatesFailedAssociation(t *testing.T) {
	failed := &failedWritePacketConn{newTestPacketConn(0)}
	replacement := newChannelPacketConn()
	var calls atomic.Int32
	port, err := New(Options{DialPacketConn: func(context.Context, M.Socksaddr) (N.NetPacketConn, error) {
		if calls.Add(1) == 1 {
			return failed, nil
		}
		return replacement, nil
	}})
	require.NoError(t, err)
	defer port.Close()
	packet := testPortPacket(t, 50000, "retry")
	require.NoError(t, port.WritePackets([][]byte{packet}))
	receiveTestValue(t, failed.closed)
	require.NoError(t, port.WritePackets([][]byte{packet}))
	require.Equal(t, []byte("retry"), receiveTestValue(t, replacement.sent).payload)
	require.Equal(t, int32(2), calls.Load())
}

type lateReadPacketConn struct {
	*testPacketConn
	started chan struct{}
	release chan struct{}
}

func (c *lateReadPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	close(c.started)
	<-c.release
	buffer.Write([]byte("late reply"))
	return M.SocksaddrFromNetIP(netip.MustParseAddrPort("203.0.113.1:443")), nil
}

type testReturn struct{ packets chan []byte }

func newTestReturn() *testReturn          { return &testReturn{make(chan []byte, 4)} }
func (r *testReturn) ReturnHeadroom() int { return 0 }
func (r *testReturn) ReturnPackets(packets [][]byte) [][]byte {
	for _, packet := range packets {
		r.packets <- append([]byte(nil), packet...)
	}
	return nil
}

func TestPortDetachDropsLateReplies(t *testing.T) {
	oldConn := &lateReadPacketConn{testPacketConn: newTestPacketConn(0), started: make(chan struct{}), release: make(chan struct{})}
	newConn := newChannelPacketConn()
	var calls atomic.Int32
	port, err := New(Options{DialPacketConn: func(context.Context, M.Socksaddr) (N.NetPacketConn, error) {
		if calls.Add(1) == 1 {
			return oldConn, nil
		}
		return newConn, nil
	}})
	require.NoError(t, err)
	defer port.Close()
	// Release the old read even if an assertion fails, so Close can join it.
	defer close(oldConn.release)
	oldReturn, newReturn := newTestReturn(), newTestReturn()
	require.NoError(t, port.AttachReturn(oldReturn))
	require.NoError(t, port.AttachReturn(oldReturn), "reattaching the same dispatcher is idempotent")
	require.Error(t, port.AttachReturn(newReturn))
	packet := testPortPacket(t, 50000, "query")
	require.NoError(t, port.WritePackets([][]byte{packet}))
	receiveTestValue(t, oldConn.started)
	require.NoError(t, port.DetachReturn(newReturn), "an unrelated detach must preserve the active binding")
	require.Error(t, port.AttachReturn(newReturn))
	require.NoError(t, port.DetachReturn(oldReturn))
	receiveTestValue(t, oldConn.closed)
	require.NoError(t, port.AttachReturn(newReturn))
	require.NoError(t, port.WritePackets([][]byte{packet}))
	receiveTestValue(t, newConn.sent)
	newConn.received <- testDatagram{[]byte("new reply"), M.SocksaddrFromNetIP(netip.MustParseAddrPort("203.0.113.1:443"))}
	_, _, payload, ok := parseUDPPacket(receiveTestValue(t, newReturn.packets))
	require.True(t, ok)
	require.Equal(t, []byte("new reply"), payload)
	// Run the late read after rebinding, and join all workers before checking
	// that neither return path received the old association's reply.
	oldConn.release <- struct{}{}
	require.NoError(t, port.Close())
	require.Empty(t, oldReturn.packets)
	require.Empty(t, newReturn.packets)
}

// Closing and resetting may race with new packets and successful dials. Every
// connection returned by a factory still belongs to the port and must close.
func TestPortConcurrentResetAndClose(t *testing.T) {
	var access sync.Mutex
	var connections []*testPacketConn
	started := make(chan struct{})
	var once sync.Once
	port, err := New(Options{DialPacketConn: func(context.Context, M.Socksaddr) (N.NetPacketConn, error) {
		conn := newTestPacketConn(0)
		access.Lock()
		connections = append(connections, conn)
		access.Unlock()
		once.Do(func() { close(started) })
		return conn, nil
	}})
	require.NoError(t, err)
	defer port.Close()
	var writers sync.WaitGroup
	start := make(chan struct{})
	for index := range 8 {
		packet := testPortPacket(t, uint16(50000+index), "concurrent")
		writers.Add(1)
		go func() {
			defer writers.Done()
			<-start
			for range 64 {
				port.WritePackets([][]byte{packet})
			}
		}()
	}
	close(start)
	receiveTestValue(t, started)
	for range 16 {
		port.Reset()
	}
	require.NoError(t, port.Close())
	writers.Wait()
	require.ErrorIs(t, port.AttachReturn(newTestReturn()), net.ErrClosed)
	require.Zero(t, port.queuedBytes)
	for _, conn := range connections {
		receiveTestValue(t, conn.closed)
	}
}
