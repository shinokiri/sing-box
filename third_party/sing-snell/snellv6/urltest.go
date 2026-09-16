package snellv6

import (
	"context"
	"net"
	"sync"

	"github.com/sagernet/sing-snell/internal/reuse"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// URLTestDialer reserves one physical session for a warmup and one measured
// request. It never publishes that session to the shared business pool and
// never silently redials after the warmup. Close releases the reservation.
// The target TCP/TLS connection is still recreated for each logical request.
type URLTestDialer struct {
	client     *Client
	ctx        context.Context
	cancel     context.CancelFunc
	access     sync.Mutex
	session    *reuseSession
	dials      int
	ready      chan struct{}
	readyOnce  sync.Once
	stopDial   func() bool
	cancelDial context.CancelFunc
}

func (c *Client) NewURLTestDialer(ctx context.Context) (*URLTestDialer, error) {
	if !c.reuse {
		return nil, E.New("snell: URLTest reservation requires reuse")
	}
	ctx, cancel := context.WithCancel(ctx)
	return &URLTestDialer{client: c, ctx: ctx, cancel: cancel, ready: make(chan struct{})}, nil
}

func (d *URLTestDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) != N.NetworkTCP {
		return nil, E.New("snell: URLTest reservation requires TCP")
	}
	d.access.Lock()
	defer d.access.Unlock()
	if err := d.ctx.Err(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	switch d.dials {
	case 0:
		if d.client.pool.IsClosed() {
			return nil, net.ErrClosed
		}
		if d.client.dialer == nil {
			return nil, E.New("snell: missing dialer")
		}
		// Keep the caller's routing/KeepSession values. Cancellation of the
		// reservation must also interrupt a dial (including a lazy TFO write).
		dialCtx, cancel := context.WithCancel(ctx)
		d.cancelDial = cancel
		d.stopDial = context.AfterFunc(d.ctx, cancel)
		conn, err := d.client.dialer.DialContext(dialCtx, N.NetworkTCP, d.client.server)
		if err != nil {
			d.stopDial()
			cancel()
			return nil, err
		}
		d.session = d.client.newReuseSession(conn)
		d.session.urlTest = d
		d.session.state.Store(uint32(reuse.StateActive))
		if d.ctx.Err() != nil || ctx.Err() != nil || d.client.pool.IsClosed() {
			d.session.Close()
			return nil, net.ErrClosed
		}
	case 1:
		// Closing the warm HEAD only starts the Snell EOF drain. Wait for
		// its completion before returning the measured logical connection.
		select {
		case <-d.ready:
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-d.ctx.Done():
			return nil, d.ctx.Err()
		}
		if !d.session.state.CompareAndSwap(uint32(reuse.StateReady), uint32(reuse.StateActive)) {
			return nil, E.New("snell: URLTest warm session is not reusable")
		}
	default:
		return nil, E.New("snell: URLTest reservation already used")
	}
	d.dials++
	return d.session.DialConn(destination)
}

func (d *URLTestDialer) signalReady() {
	d.readyOnce.Do(func() { close(d.ready) })
}

func (d *URLTestDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, E.New("snell: URLTest reservation does not support UDP")
}

func (d *URLTestDialer) Close() error {
	// Cancel before taking access: DialContext may hold it while waiting
	// for either the initial TCP dial or the server's warmup EOF.
	d.cancel()
	d.access.Lock()
	defer d.access.Unlock()
	if d.stopDial != nil {
		d.stopDial()
		d.cancelDial()
	}
	if d.session != nil {
		return d.session.Close()
	}
	return nil
}
