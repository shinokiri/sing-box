package dialer

import (
	"context"
	"errors"
	"io"
	"math"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/json/badoption"

	"golang.org/x/sys/unix"
)

func timeoutTestDialer(t *testing.T, timeout time.Duration) *DefaultDialer {
	t.Helper()
	d, err := NewDefault(context.Background(), option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{
		TCPUserTimeout: common.Ptr(badoption.Duration(timeout)), DisableTCPKeepAlive: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func timeoutTestPair(t *testing.T, timeout time.Duration, network string, smallWindow bool) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	address := "127.0.0.1:0"
	if network == "tcp6" {
		address = "[::1]:0"
	}
	var lc net.ListenConfig
	if smallWindow {
		lc.Control = func(network, address string, raw syscall.RawConn) error {
			return control.Raw(raw, func(fd uintptr) error {
				return unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, 4096)
			})
		}
	}
	listener, err := lc.Listen(context.Background(), network, address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	d := timeoutTestDialer(t, timeout)
	var conn net.Conn
	if network == "tcp6" {
		conn, err = d.dialer6.DialContext(context.Background(), network, listener.Addr().String(), nil)
	} else {
		conn, err = d.dialer4.DialContext(context.Background(), network, listener.Addr().String(), nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	client := conn.(*net.TCPConn)
	t.Cleanup(func() { client.Close() })
	conn, err = listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	server := conn.(*net.TCPConn)
	t.Cleanup(func() { server.Close() })
	return client, server
}

func TestTCPUserTimeoutSocketOptions(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		for _, timeout := range []time.Duration{0, 1, 30 * time.Second, time.Duration(math.MaxInt32) * time.Millisecond} {
			t.Run(network+"/"+timeout.String(), func(t *testing.T) {
				client, _ := timeoutTestPair(t, timeout, network, false)
				err := control.Conn(client, func(fd uintptr) error {
					value, err := unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT)
					if err != nil {
						return err
					}
					want := int((timeout + time.Millisecond - 1) / time.Millisecond)
					if value != want {
						t.Errorf("TCP_USER_TIMEOUT=%d want %d", value, want)
					}
					ka, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_KEEPALIVE)
					if err != nil {
						return err
					}
					if ka != 0 {
						t.Errorf("keepalive unexpectedly enabled: %d", ka)
					}
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestTCPUserTimeoutInvalid(t *testing.T) {
	for _, timeout := range []time.Duration{-1, time.Duration(math.MaxInt32)*time.Millisecond + 1, time.Duration(math.MaxInt64)} {
		_, err := NewDefault(context.Background(), option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{TCPUserTimeout: common.Ptr(badoption.Duration(timeout))}})
		if err == nil {
			t.Errorf("accepted out-of-range timeout %s", timeout)
		}
	}
}

func TestTCPUserTimeoutUDP(t *testing.T) {
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	d := timeoutTestDialer(t, time.Second)
	conn, err := d.udpDialer4.DialContext(context.Background(), "udp4", listener.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err = conn.Write([]byte("udp remains usable")); err != nil {
		t.Fatal(err)
	}
	listener.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 64)
	n, _, err := listener.ReadFrom(b)
	if err != nil || string(b[:n]) != "udp remains usable" {
		t.Fatalf("UDP echo receiver: %q %v", b[:n], err)
	}
}

func TestTCPUserTimeoutAllowsIdleAndDelayedReply(t *testing.T) {
	t.Parallel()
	client, server := timeoutTestPair(t, time.Second, "tcp4", false)
	// Completely idle for longer than the configured timeout.
	time.Sleep(2200 * time.Millisecond)
	if _, err := client.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	request := make([]byte, 7)
	server.SetReadDeadline(time.Now().Add(time.Second))
	if n, err := io.ReadFull(server, request); err != nil || n != 7 {
		t.Fatalf("request: %d %v", n, err)
	}
	// TCP acknowledged the request; application computation need not finish
	// within TCP_USER_TIMEOUT. Also check the kernel send state below.
	time.Sleep(2200 * time.Millisecond)
	err := control.Conn(client, func(fd uintptr) error {
		info, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
		if err == nil && info.Unacked != 0 {
			t.Errorf("request still unacknowledged: %d", info.Unacked)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.Write([]byte("answer")); err != nil {
		t.Fatal(err)
	}
	client.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 6)
	if n, err := io.ReadFull(client, b); err != nil || string(b[:n]) != "answer" {
		t.Fatalf("delayed reply: %q %v", b[:n], err)
	}
}

func TestTCPUserTimeoutZeroWindow(t *testing.T) {
	t.Parallel()
	client, _ := timeoutTestPair(t, time.Second, "tcp4", true)
	writer := make(chan error, 1)
	start := time.Now()
	go func() { _, err := client.Write(make([]byte, 256*1024)); writer <- err }()
	client.SetReadDeadline(time.Now().Add(6 * time.Second))
	_, err := client.Read(make([]byte, 1))
	if !errors.Is(err, syscall.ETIMEDOUT) {
		t.Fatalf("expected kernel ETIMEDOUT, got %v", err)
	}
	if elapsed := time.Since(start); elapsed < time.Second || elapsed > 5*time.Second {
		t.Errorf("unexpected kernel timeout interval %s", elapsed)
	}
	client.Close()
	select {
	case <-writer:
	case <-time.After(time.Second):
		t.Fatal("writer failed to exit")
	}
}

// Loss is confined to receiver sockets owned by this test. No global firewall,
// interface, network namespace, VPN configuration or external server is used.
func TestTCPUserTimeoutUnacknowledgedData(t *testing.T) {
	t.Parallel()
	candidate, candidatePeer := timeoutTestPair(t, time.Second, "tcp4", false)
	baseline, baselinePeer := timeoutTestPair(t, 0, "tcp4", false)
	for _, peer := range []*net.TCPConn{candidatePeer, baselinePeer} {
		err := control.Conn(peer, func(fd uintptr) error {
			instruction := unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: 0}
			program := unix.SockFprog{Len: 1, Filter: &instruction}
			return unix.SetsockoptSockFprog(int(fd), unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &program)
		})
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			t.Skipf("kernel restricts classic TCP socket filters: %v", err)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	start := time.Now()
	for _, client := range []*net.TCPConn{candidate, baseline} {
		if _, err := client.Write([]byte("request")); err != nil {
			t.Fatal(err)
		}
	}
	// Verify actual unacknowledged TCP data, rather than an application that
	// merely has not replied, before waiting for the candidate's failure.
	for _, client := range []*net.TCPConn{candidate, baseline} {
		err := control.Conn(client, func(fd uintptr) error {
			info, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
			if err == nil && info.Unacked == 0 {
				t.Error("loss fixture did not leave unacknowledged data")
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	candidate.SetReadDeadline(time.Now().Add(6 * time.Second))
	_, err := candidate.Read(make([]byte, 1))
	if !errors.Is(err, syscall.ETIMEDOUT) {
		t.Fatalf("expected kernel ETIMEDOUT, got %v", err)
	}
	elapsed := time.Since(start)
	if elapsed < 900*time.Millisecond || elapsed > 5*time.Second {
		t.Errorf("unexpected timeout interval %s", elapsed)
	}
	err = control.Conn(baseline, func(fd uintptr) error {
		info, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
		if err == nil {
			if info.State != 1 || info.Unacked == 0 || info.Total_retrans == 0 {
				t.Errorf("default timeout control not still retransmitting: state=%d unacked=%d retrans=%d", info.State, info.Unacked, info.Total_retrans)
			}
			t.Logf("candidate ETIMEDOUT after %s; default control state=%d unacked=%d total_retrans=%d", elapsed, info.State, info.Unacked, info.Total_retrans)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = control.Conn(baselinePeer, func(fd uintptr) error {
		return unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_DETACH_FILTER, 0)
	}); err != nil {
		t.Fatal(err)
	}
	baselinePeer.SetReadDeadline(time.Now().Add(5 * time.Second))
	request := make([]byte, 7)
	if _, err = io.ReadFull(baselinePeer, request); err != nil || string(request) != "request" {
		t.Fatalf("control failed to recover after loss removed: %q %v", request, err)
	}
	t.Log("default control delivered its buffered request after test filter was removed")
}
