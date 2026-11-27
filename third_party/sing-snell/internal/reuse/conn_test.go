package reuse

import (
	"io"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
)

type countedIdleConn struct {
	net.Conn
	reads atomic.Int32
}

func (c *countedIdleConn) Read(p []byte) (int, error) {
	c.reads.Add(1)
	return c.Conn.Read(p)
}

func TestIdleReadSurvivesBufferedCheckout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		left, right := net.Pipe()
		defer left.Close()
		defer right.Close()
		raw := &countedIdleConn{Conn: left}
		transport := &Conn{Conn: raw}
		var state atomic.Uint32
		state.Store(uint32(StateActive))
		for range 2 {
			if !transport.Ready(&state, StateActive) {
				t.Fatal("could not enter idle state")
			}
			synctest.Wait()
			if n := raw.reads.Load(); n != 1 {
				t.Fatalf("started %d idle reads", n)
			}
			if !state.CompareAndSwap(uint32(StateReady), uint32(StateActive)) {
				t.Fatal("could not check out healthy transport")
			}
			// A response that the decoder prefetched needs no transport read.
		}
		go func() { right.Write([]byte("ok")) }()
		var response [2]byte
		if _, err := io.ReadFull(transport, response[:]); err != nil || string(response[:]) != "ok" {
			t.Fatalf("resumed stream %q: %v", response, err)
		}
	})
}
