package snellv6

import (
	"bytes"
	"errors"
	"io"
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
