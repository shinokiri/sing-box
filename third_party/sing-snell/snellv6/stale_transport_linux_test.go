//go:build linux

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
	M "github.com/sagernet/sing/common/metadata"
)

// A peer can finish a request normally and then close the idle TCP connection.
// A new logical request must not receive that dead socket from the pool.
func TestIdlePeerFINDoesNotReturnSessionToPool(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	physical, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer physical.Close()
	peer, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	physical.SetDeadline(time.Now().Add(3 * time.Second))
	psk := []byte("public idle peer FIN fixture")
	client, _ := NewClient(ClientOptions{PSK: psk, Reuse: true})
	defer client.Close()
	wire, _ := receiveWire(t, psk, [][]byte{{snell.ReplyTunnel, 42}, nil})
	done := make(chan error, 1)
	go func() {
		_, e := peer.Write(wire)
		if e == nil {
			e = peer.(*net.TCPConn).CloseWrite()
		}
		done <- e
		io.Copy(io.Discard, peer)
	}()
	session := client.newReuseSession(physical)
	session.state.Store(uint32(reuse.StateActive))
	logical, err := session.DialConn(M.ParseSocksaddr("fixture.invalid:443"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(logical)
	if err != nil || !bytes.Equal(data, []byte{42}) {
		t.Fatal(data, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := logical.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	// Give the loopback FIN time to enter the receive queue; no network delay.
	time.Sleep(20 * time.Millisecond)
	_, found, _ := client.pool.Take()
	if found {
		t.Fatal("BUG: already FIN-closed TCP socket was handed to a new request")
	}
}
