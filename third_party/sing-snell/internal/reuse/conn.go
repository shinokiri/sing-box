package reuse

import (
	"net"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

type Conn struct {
	net.Conn
	OnIdleClose func()
	access      sync.Mutex
	watch       *watch
}

type watch struct {
	done chan struct{}
	data [1]byte
	n    int
	err  error
}

func (w *watch) ended() bool {
	select {
	case <-w.done:
		return w.n == 0 && w.err != nil && !E.IsTimeout(w.err)
	default:
		return false
	}
}

func (c *Conn) Ready(state *atomic.Uint32, from State) bool {
	c.access.Lock()
	if c.watch != nil && c.watch.ended() {
		closed := state.CompareAndSwap(uint32(from), uint32(StateClosed))
		c.access.Unlock()
		if closed {
			c.closeIdle()
		}
		return false
	}
	if !state.CompareAndSwap(uint32(from), uint32(StateReady)) {
		c.access.Unlock()
		return false
	}
	if c.watch != nil {
		// A buffered decoder can complete a whole request before it needs
		// the pending transport read. Only one goroutine may own that byte.
		c.access.Unlock()
		return true
	}
	idle := &watch{done: make(chan struct{})}
	c.watch = idle
	c.access.Unlock()
	go func() {
		idle.n, idle.err = c.Conn.Read(idle.data[:])
		c.access.Lock()
		closed := c.watch == idle && state.CompareAndSwap(uint32(StateReady), uint32(StateClosed))
		close(idle.done)
		c.access.Unlock()
		if closed {
			c.closeIdle()
		}
	}()
	return true
}

func (c *Conn) closeIdle() {
	c.Conn.Close()
	if c.OnIdleClose != nil {
		c.OnIdleClose()
	}
}

func (c *Conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.access.Lock()
	idle := c.watch
	c.watch = nil
	c.access.Unlock()
	if idle == nil {
		return c.Conn.Read(p)
	}
	<-idle.done
	if idle.n == 0 && E.IsTimeout(idle.err) {
		return c.Conn.Read(p)
	}
	return copy(p, idle.data[:idle.n]), idle.err
}

func (c *Conn) Upstream() any {
	return c.Conn
}

func (c *Conn) WriterReplaceable() bool {
	return true
}

var (
	_ common.WithUpstream  = (*Conn)(nil)
	_ N.WriterWithUpstream = (*Conn)(nil)
)
