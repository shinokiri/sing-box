// Package preconnect prepares a bounded spare TCP connection after actual demand.
package preconnect

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const idleTimeout = 5 * time.Second

// Dialer is only suitable for an eager TCP dialer and a peer that sends no data
// before the client request. It never sends probes or keeps an idle pool alive.
type Dialer struct {
	N.Dialer
	server      M.Socksaddr
	ctx         context.Context
	access      sync.Mutex
	enabled     bool
	closed      bool
	epoch       uint64
	spare       *idleConn
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	idleTimeout time.Duration
}

func New(ctx context.Context, dialer N.Dialer, server M.Socksaddr) *Dialer {
	return &Dialer{Dialer: dialer, server: server, ctx: ctx, enabled: true, idleTimeout: idleTimeout}
}

func (d *Dialer) DialContext(ctx context.Context, network string, address M.Socksaddr) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if network != N.NetworkTCP || address != d.server {
		return d.Dialer.DialContext(ctx, network, address)
	}
	d.access.Lock()
	if d.closed {
		d.access.Unlock()
		return nil, net.ErrClosed
	}
	epoch := d.epoch
	spare := d.spare
	d.spare = nil
	d.access.Unlock()
	var conn net.Conn
	if spare != nil {
		conn = spare.take()
	}
	d.access.Lock()
	if epoch != d.epoch && conn != nil {
		conn.Close()
		conn = nil
	}
	d.access.Unlock()
	if err := ctx.Err(); err != nil {
		if conn != nil {
			conn.Close()
		}
		return nil, err
	}
	if conn == nil {
		var err error
		conn, err = d.Dialer.DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
	}
	d.access.Lock()
	valid := !d.closed
	d.access.Unlock()
	if !valid {
		conn.Close()
		return nil, net.ErrClosed
	}
	// Reuse in the protocol's own pool remains the first choice. This dialer
	// is reached only when that pool needs another physical TCP connection.
	d.prepare(epoch)
	return conn, nil
}

func (d *Dialer) prepare(epoch uint64) {
	d.access.Lock()
	if d.closed || !d.enabled || epoch != d.epoch || d.spare != nil || d.cancel != nil {
		d.access.Unlock()
		return
	}
	ctx, cancel := context.WithTimeout(d.ctx, idleTimeout)
	d.cancel = cancel
	d.wg.Add(1)
	d.access.Unlock()
	go func() {
		defer d.wg.Done()
		defer cancel()
		conn, err := d.Dialer.DialContext(ctx, N.NetworkTCP, d.server)
		d.access.Lock()
		defer d.access.Unlock()
		if d.closed || epoch != d.epoch || !d.enabled || ctx.Err() != nil {
			if conn != nil {
				conn.Close()
			}
			if epoch == d.epoch {
				d.cancel = nil
			}
			return
		}
		d.cancel = nil
		if err == nil {
			d.spare = newIdleConn(conn, d.idleTimeout)
		}
	}()
}

// Reset cancels speculative work and retires the spare on a network change.
// Connections already handed to callers are owned by those callers.
func (d *Dialer) Reset() {
	d.access.Lock()
	d.resetLocked()
	d.access.Unlock()
}

func (d *Dialer) resetLocked() {
	d.epoch++
	if d.cancel != nil {
		d.cancel()
		d.cancel = nil
	}
	if d.spare != nil {
		d.spare.conn.Close()
		d.spare = nil
	}
}

func (d *Dialer) SetEnabled(enabled bool) {
	d.access.Lock()
	d.enabled = enabled
	if !enabled {
		d.resetLocked()
	}
	d.access.Unlock()
}

func (d *Dialer) Close() error {
	d.access.Lock()
	d.closed = true
	d.resetLocked()
	d.access.Unlock()
	d.wg.Wait()
	return nil
}

type idleConn struct {
	conn    net.Conn
	expires time.Time
	access  sync.Mutex
	claimed bool
	done    chan struct{}
	n       int
	err     error
}

func newIdleConn(conn net.Conn, maxAge time.Duration) *idleConn {
	s := &idleConn{conn: conn, expires: time.Now().Add(maxAge), done: make(chan struct{})}
	if err := conn.SetReadDeadline(s.expires); err != nil {
		s.err = err
		conn.Close()
		close(s.done)
		return s
	}
	go func() {
		var b [1]byte
		s.n, s.err = conn.Read(b[:])
		s.access.Lock()
		if !s.claimed {
			conn.Close()
		}
		s.access.Unlock()
		close(s.done)
	}()
	return s
}

// Stop the idle read before handing off the original connection. A peer EOF,
// unsolicited data, or expiry discards the spare before any user data is sent.
// No wrapper or read goroutine remains in the active data path.
func (s *idleConn) take() net.Conn {
	s.access.Lock()
	s.claimed = true
	err := s.conn.SetReadDeadline(time.Now())
	s.access.Unlock()
	if err != nil {
		s.conn.Close()
	}
	<-s.done
	var timeout net.Error
	if err != nil || s.n != 0 || !errors.As(s.err, &timeout) || !timeout.Timeout() || !time.Now().Before(s.expires) {
		s.conn.Close()
		return nil
	}
	if s.conn.SetReadDeadline(time.Time{}) != nil {
		s.conn.Close()
		return nil
	}
	return s.conn
}
