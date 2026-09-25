package dialer

import (
	"context"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/database64128/tfo-go/v2"
)

type slowOpenConn struct {
	dialer      *tfo.Dialer
	prepare     func() (*tfo.Dialer, error)
	ctx         context.Context
	cancel      context.CancelFunc
	netns       string
	network     string
	destination M.Socksaddr
	conn        atomic.Pointer[net.TCPConn]
	create      chan struct{}
	done        chan struct{}
	access      sync.Mutex
	closeOnce   sync.Once
	err         error
}

func DialSlowContext(dialer *tfo.Dialer, ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return dialSlowContext(dialer, ctx, network, destination, "")
}

func dialSlowContext(dialer *tfo.Dialer, ctx context.Context, network string, destination M.Socksaddr, netns string) (net.Conn, error) {
	if dialer.DisableTFO || N.NetworkName(network) != N.NetworkTCP {
		switch N.NetworkName(network) {
		case N.NetworkTCP, N.NetworkUDP:
			return dialer.Dialer.DialContext(ctx, network, destination.String())
		default:
			return dialer.Dialer.DialContext(ctx, network, destination.AddrString())
		}
	}
	return newSlowOpenConn(dialer, ctx, network, destination, netns, nil), nil
}

func newSlowOpenConn(dialer *tfo.Dialer, ctx context.Context, network string, destination M.Socksaddr, netns string, prepare func() (*tfo.Dialer, error)) *slowOpenConn {
	ctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	return &slowOpenConn{
		dialer:      dialer,
		prepare:     prepare,
		ctx:         ctx,
		cancel:      cancel,
		netns:       netns,
		network:     network,
		destination: destination,
		create:      make(chan struct{}),
		done:        make(chan struct{}),
	}
}

func (c *slowOpenConn) Read(b []byte) (n int, err error) {
	conn := c.conn.Load()
	if conn != nil {
		return conn.Read(b)
	}
	select {
	case <-c.create:
		if c.err != nil {
			return 0, c.err
		}
		return c.conn.Load().Read(b)
	case <-c.done:
		return 0, os.ErrClosed
	}
}

func (c *slowOpenConn) Write(b []byte) (n int, err error) {
	tcpConn := c.conn.Load()
	if tcpConn != nil {
		return tcpConn.Write(b)
	}
	c.access.Lock()
	defer c.access.Unlock()
	select {
	case <-c.create:
		if c.err != nil {
			return 0, c.err
		}
		return c.conn.Load().Write(b)
	case <-c.done:
		return 0, os.ErrClosed
	default:
	}
	// TFO opens the socket on the first write, so enter the namespace here.
	conn, err := listener.ListenNetworkNamespace[net.Conn](c.ctx, c.netns, func() (net.Conn, error) {
		dialer := c.dialer
		if c.prepare != nil {
			var err error
			dialer, err = c.prepare()
			if err != nil {
				return nil, err
			}
		}
		return dialer.DialContext(c.ctx, c.network, c.destination.String(), b)
	})
	if err == nil {
		c.conn.Store(conn.(*net.TCPConn))
		// Close may run while the first write is creating the socket.
		select {
		case <-c.done:
			conn.Close()
			err = os.ErrClosed
		default:
			n = len(b)
		}
	}
	c.err = err
	close(c.create)
	return
}

func (c *slowOpenConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.done)
		c.cancel()
		conn := c.conn.Load()
		if conn != nil {
			conn.Close()
		}
	})
	return nil
}

func (c *slowOpenConn) LocalAddr() net.Addr {
	conn := c.conn.Load()
	if conn == nil {
		return M.Socksaddr{}
	}
	return conn.LocalAddr()
}

func (c *slowOpenConn) RemoteAddr() net.Addr {
	conn := c.conn.Load()
	if conn == nil {
		return M.Socksaddr{}
	}
	return conn.RemoteAddr()
}

func (c *slowOpenConn) SetDeadline(t time.Time) error {
	conn := c.conn.Load()
	if conn == nil {
		return os.ErrInvalid
	}
	return conn.SetDeadline(t)
}

func (c *slowOpenConn) SetReadDeadline(t time.Time) error {
	conn := c.conn.Load()
	if conn == nil {
		return os.ErrInvalid
	}
	return conn.SetReadDeadline(t)
}

func (c *slowOpenConn) SetWriteDeadline(t time.Time) error {
	conn := c.conn.Load()
	if conn == nil {
		return os.ErrInvalid
	}
	return conn.SetWriteDeadline(t)
}

func (c *slowOpenConn) Upstream() any {
	return common.PtrOrNil(c.conn.Load())
}

func (c *slowOpenConn) ReaderReplaceable() bool {
	return c.conn.Load() != nil
}

func (c *slowOpenConn) WriterReplaceable() bool {
	return c.conn.Load() != nil
}

func (c *slowOpenConn) NeedHandshake() bool {
	return c.conn.Load() == nil
}

func (c *slowOpenConn) WriteTo(w io.Writer) (n int64, err error) {
	conn := c.conn.Load()
	if conn == nil {
		select {
		case <-c.create:
			if c.err != nil {
				return 0, c.err
			}
		case <-c.done:
			return 0, os.ErrClosed
		}
	}
	return bufio.Copy(w, c.conn.Load())
}
