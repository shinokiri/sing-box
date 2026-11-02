package snellv6

import (
	"bytes"
	"io"
	"testing"
)

type helloPreparedConn struct {
	helloMemoryConn
	compat   bool
	handle   uint64
	prepares int
}

func (c *helloPreparedConn) PrepareTFO() (bool, uint64) {
	c.prepares++
	return c.compat, c.handle
}

func TestHelloCellularMarkerAndCapacityUseOnePreparation(t *testing.T) {
	for _, compat := range []bool{false, true} {
		transport, err := NewHelloTransport(helloTestPSK)
		if err != nil {
			t.Fatal(err)
		}
		// The same endpoint on a different network must not seed this SYN.
		transport.remember("192.0.2.1:443", 0, 99, 1392)
		transport.remember("192.0.2.1:443", 0, 101, 400)
		raw := &helloPreparedConn{compat: compat, handle: 101}
		conn := transport.Wrap(raw, "ignored").(*helloConn)
		conn.mu.Lock()
		budget, _ := conn.firstFrameBudget()
		conn.mu.Unlock()
		if budget != 400 || raw.prepares != 1 {
			t.Fatal(budget, raw.prepares)
		}
		// A second policy read during framing would select a different marker
		// and a different capacity. The previously prepared choice must win.
		raw.compat = !compat
		raw.handle = 99
		original, _ := receiveWire(t, helloTestPSK, [][]byte{bytes.Repeat([]byte("x"), 1024)})
		if _, err := conn.Write(original); err != nil {
			t.Fatal(err)
		}
		encoded := append([]byte(nil), raw.Bytes()...)
		marked := bytes.Equal(encoded[11:19], []byte("CTFO\x01\x00\x00\x00"))
		if marked != compat || raw.prepares != 1 {
			t.Fatal("marker reselected the network", marked, raw.prepares)
		}
		reader := bytes.NewReader(encoded)
		prefix, err := transport.DecodeHello(reader)
		if err != nil {
			t.Fatal(err)
		}
		tail, _ := io.ReadAll(reader)
		if !bytes.Equal(append(prefix, tail...), original) {
			t.Fatal("marker altered the Snell stream")
		}
	}
}

func TestHelloCapacitySeparatesNetworkHandles(t *testing.T) {
	transport, _ := NewHelloTransport(helloTestPSK)
	peer := "192.0.2.1:443"
	transport.remember(peer, 0, 101, 1392)
	if n, source := transport.budget(new(helloMemoryConn), peer, 0, 102); n != helloColdBudget || source != "cold_estimate" {
		t.Fatal("another network's MSS escaped into this SYN", n, source)
	}
	if n, source := transport.budget(new(helloMemoryConn), peer, 0, 101); n != 1392 || source != "observed_peer" {
		t.Fatal("same-network observation was lost", n, source)
	}
}
