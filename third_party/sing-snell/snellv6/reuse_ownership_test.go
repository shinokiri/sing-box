package snellv6

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-snell/internal/reuse"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

type ownershipBlockingConn struct {
	net.Conn
	block   atomic.Bool
	started chan struct{}
}

func (c *ownershipBlockingConn) Write(p []byte) (int, error) {
	if !c.block.Load() {
		return len(p), nil
	}
	select {
	case c.started <- struct{}{}:
	default:
	}
	return c.Conn.Write(p)
}

// Close must interrupt an active write, not wait for its writer lock, and it
// must never publish a possibly partial record to the next logical request.
func TestReuseCloseInterruptsWrite(t *testing.T) {
	for _, established := range []bool{false, true} {
		name := "first-record"
		if established {
			name = "subsequent-record"
		}
		t.Run(name, func(t *testing.T) {
			client, err := NewClient(ClientOptions{PSK: []byte("public ownership fixture"), Reuse: true})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			source, sink := net.Pipe()
			defer source.Close()
			defer sink.Close()
			raw := &ownershipBlockingConn{Conn: source, started: make(chan struct{}, 1)}
			session := client.newReuseSession(raw)
			session.state.Store(uint32(reuse.StateActive))
			logical, err := session.DialConn(M.ParseSocksaddr("probe.test:443"))
			if err != nil {
				t.Fatal(err)
			}
			conn := logical.(*reuseConn)
			if established {
				if _, err = conn.Write([]byte("initial data")); err != nil {
					t.Fatal(err)
				}
			}
			conn.replyRead.Store(true)
			raw.block.Store(true)
			written := make(chan error, 1)
			go func() { _, err := conn.Write([]byte("blocked data")); written <- err }()
			select {
			case <-raw.started:
			case <-time.After(time.Second):
				t.Fatal("write did not start")
			}
			closed := make(chan error, 1)
			go func() { closed <- conn.Close() }()
			select {
			case err := <-closed:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("Close waited for the blocked writer")
			}
			select {
			case err := <-written:
				if err == nil {
					t.Fatal("blocked write succeeded after transport close")
				}
			case <-time.After(time.Second):
				t.Fatal("Close did not interrupt the write")
			}
			if reuse.State(session.state.Load()) != reuse.StateClosed {
				t.Fatal("partially written session was kept reusable")
			}
		})
	}
}

// Buffer and vector paths transfer ownership even when rejecting a write.
// They must apply the same logical lifetime rule as net.Conn.Write.
func TestReuseClosedWriteVariants(t *testing.T) {
	conn := &reuseConn{}
	conn.closed.Store(true)
	buffer := func() *buf.Buffer { b := buf.NewSize(16); b.Write([]byte("old request")); return b }
	if _, err := conn.Write([]byte("old request")); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	if err := conn.WriteBuffer(buffer()); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	writer := &reuseVectorisedWriter{conn: conn}
	if err := writer.WriteVectorised([]*buf.Buffer{buffer(), buffer()}); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	if err := conn.CloseWrite(); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}
