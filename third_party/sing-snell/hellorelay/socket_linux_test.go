//go:build linux

package hellorelay

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func tcpOption(t *testing.T, conn syscall.Conn, option int) int {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var value int
	var optionErr error
	err = raw.Control(func(fd uintptr) { value, optionErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, option) })
	if err != nil || optionErr != nil {
		t.Fatal(err, optionErr)
	}
	return value
}

func TestReceiverTFOOptionsRemainPerSocket(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		for _, enabled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/enabled_%v", host, enabled), func(t *testing.T) {
				s, err := New(Options{Mode: PassThrough, Upstream: "127.0.0.1:1", ListenTFO: enabled, TFOQueue: 23})
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				l, err := s.Listen(net.JoinHostPort(host, "0"))
				if err != nil {
					t.Fatal(err)
				}
				defer l.Close()
				queue := tcpOption(t, l.(*net.TCPListener), unix.TCP_FASTOPEN)
				want := 0
				if enabled {
					want = 23
				}
				if queue != want {
					t.Fatalf("listen TFO=%d expected %d", queue, want)
				}
				d := net.Dialer{Timeout: time.Second, Control: dialControl(enabled)}
				c, err := d.DialContext(context.Background(), "tcp", l.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				value := tcpOption(t, c.(*net.TCPConn), unix.TCP_FASTOPEN_CONNECT)
				want = 0
				if enabled {
					want = 1
				}
				if value != want {
					t.Fatalf("outgoing TFO=%d expected %d", value, want)
				}
			})
		}
	}
}
