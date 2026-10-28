//go:build linux

package reuse

import (
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
)

// Match the syscall/Upstream behavior of SFA trackedConn over slowOpenConn
// after its first write has opened the TCP socket.
type metadataDeferredConn struct{ net.Conn }

func (c metadataDeferredConn) Upstream() any           { return c.Conn }
func (c metadataDeferredConn) ReaderReplaceable() bool { return true }

type metadataTrackedConn struct{ net.Conn }

func (c metadataTrackedConn) Upstream() any           { return c.Conn }
func (c metadataTrackedConn) ReaderReplaceable() bool { return true }
func (c metadataTrackedConn) SyscallConn() (syscall.RawConn, error) {
	if socket, ok := c.Conn.(syscall.Conn); ok {
		return socket.SyscallConn()
	}
	return nil, os.ErrInvalid
}

func TestTCPReceiveStateThroughDeferredTFOTracking(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	peer, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	_ = client.SetDeadline(time.Now().Add(time.Second))
	tracked := metadataTrackedConn{metadataDeferredConn{client}}
	var counted int64
	counter := bufio.NewCounterConn(tracked, []N.CountFunc{func(n int64) { counted += n }}, nil)
	for _, wrapped := range []net.Conn{tracked, counter} {
		if _, measured, reusable := TCPReceiveState(wrapped); !measured || !reusable {
			t.Fatal("healthy wrapped TCP socket was not measured", measured, reusable)
		}
	}
	if err := peer.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if n, err := client.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatal("expected peer FIN", n, err)
	}
	for _, wrapped := range []net.Conn{tracked, counter} {
		if _, _, reusable := TCPReceiveState(wrapped); reusable {
			t.Fatal("FIN-closed wrapped TCP socket was reported reusable")
		}
	}
	if counted != 0 {
		t.Fatal("metadata query changed traffic accounting", counted)
	}
}
