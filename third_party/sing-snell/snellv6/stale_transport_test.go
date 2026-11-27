package snellv6

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/internal/reuse"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

// A transport EOF must never make a physical socket reusable. It is different
// from the authenticated zero-length record that ends one logical request.
func TestTransportEOFDoesNotReturnSessionToPool(t *testing.T) {
	for _, path := range []string{"read", "buffer", "wait", "drain"} {
		t.Run(path, func(t *testing.T) {
			psk := []byte("public transport EOF fixture")
			client, err := NewClient(ClientOptions{PSK: psk, Reuse: true})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			// Valid response data followed by physical EOF, with NO Snell EOF.
			wire, _ := receiveWire(t, psk, [][]byte{{snell.ReplyTunnel, 42}})
			session := client.newReuseSession(&receiveMemoryConn{Reader: bytes.NewReader(wire)})
			session.state.Store(uint32(reuse.StateActive))
			logical, err := session.DialConn(M.ParseSocksaddr("fixture.invalid:443"))
			if err != nil {
				t.Fatal(err)
			}
			conn := logical.(*reuseConn)
			if n, err := conn.Read(make([]byte, 1)); n != 1 || err != nil {
				t.Fatal(n, err)
			}
			if path != "drain" {
				switch path {
				case "read":
					_, err = conn.Read(make([]byte, 1))
				case "buffer":
					buffer := buf.New()
					defer buffer.Release()
					err = conn.ReadBuffer(buffer)
				case "wait":
					_, err = (&reuseReadWaiter{conn: conn}).WaitReadBuffer()
				}
				if !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Fatalf("physical EOF must report transport truncation, got %v", err)
				}
			}
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
			if path == "drain" {
				deadline := time.Now().Add(time.Second)
				for reuse.State(session.state.Load()) == reuse.StateWaiting && time.Now().Before(deadline) {
					time.Sleep(time.Millisecond)
				}
				if reuse.State(session.state.Load()) == reuse.StateWaiting {
					t.Fatal("drain did not finish")
				}
			}
			_, found, _ := client.pool.Take()
			if found {
				t.Fatal("BUG: physical EOF was published as a reusable session")
			}
		})
	}
}

func TestReuseLogicalHalfCloseAcrossReadAndWritePaths(t *testing.T) {
	psk := []byte("public logical EOF fixture")
	client, err := NewClient(ClientOptions{PSK: psk, Reuse: true})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	wire, _ := receiveWire(t, psk, [][]byte{{snell.ReplyTunnel, 42}, nil, {snell.ReplyTunnel, 99}})
	session := client.newReuseSession(&receiveMemoryConn{Reader: bytes.NewReader(wire)})
	defer session.Close()
	session.state.Store(uint32(reuse.StateActive))
	destination := M.ParseSocksaddr("fixture.invalid:443")
	logical, err := session.DialConn(destination)
	if err != nil {
		t.Fatal(err)
	}
	conn := logical.(*reuseConn)
	if err = conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	afterWrite := func(err error) {
		t.Helper()
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("write after half-close returned %v", err)
		}
		if !conn.access.TryLock() {
			t.Fatal("rejected write retained the writer lock")
		}
		conn.access.Unlock()
	}
	_, err = conn.Write([]byte{1})
	afterWrite(err)
	afterWrite(conn.WriteBuffer(buf.New()))
	afterWrite((&reuseVectorisedWriter{conn: conn}).WriteVectorised([]*buf.Buffer{buf.New()}))
	if err = conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	var data [1]byte
	if n, err := conn.Read(data[:]); n != 1 || err != nil || data[0] != 42 {
		t.Fatalf("first request returned %d, %v, %v", n, err, data)
	}
	for i := 0; i < 2; i++ {
		if _, err = conn.Read(data[:]); !errors.Is(err, io.EOF) {
			t.Fatalf("read after last data returned %v", err)
		}
	}
	buffer := buf.New()
	defer buffer.Release()
	if err = conn.ReadBuffer(buffer); !errors.Is(err, io.EOF) {
		t.Fatalf("buffered read after EOF returned %v", err)
	}
	if _, err = (&reuseReadWaiter{conn: conn}).WaitReadBuffer(); !errors.Is(err, io.EOF) {
		t.Fatalf("wait after EOF returned %v", err)
	}
	if err = conn.Close(); err != nil {
		t.Fatal(err)
	}
	reused, found, _ := client.pool.Take()
	if !found || reused != session {
		t.Fatal("completed request did not return its transport to the pool")
	}
	next, err := reused.DialConn(destination)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := next.Read(data[:]); n != 1 || err != nil || data[0] != 99 {
		t.Fatalf("second request returned %d, %v, %v", n, err, data)
	}
}
