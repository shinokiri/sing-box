//go:build linux

package snellv6

import (
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// A fast one-shot peer can send its FIN before the reader gets scheduled.
// That must not leave subsequent TFO requests using a cold capacity estimate.
func TestHelloCapacityLearnsFromReplyWithFIN(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			address := "127.0.0.1:0"
			if network == "tcp6" {
				address = "[::1]:0"
			}
			listener, err := net.Listen(network, address)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			serverDone := make(chan error, 1)
			go func() {
				peer, err := listener.Accept()
				if err != nil {
					serverDone <- err
					return
				}
				defer peer.Close()
				_, err = peer.Write([]byte("reply"))
				if err == nil {
					err = peer.(*net.TCPConn).CloseWrite()
				}
				serverDone <- err
			}()
			conn, err := net.DialTimeout(network, listener.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err = conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if err = <-serverDone; err != nil {
				t.Fatal(err)
			}
			raw, err := conn.(*net.TCPConn).SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(time.Second)
			for {
				var info *unix.TCPInfo
				var infoErr error
				if err = raw.Control(func(fd uintptr) { info, infoErr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO) }); err != nil {
					t.Fatal(err)
				}
				if infoErr != nil {
					t.Fatal(infoErr)
				}
				if info.State == 8 { // Linux TCP_CLOSE_WAIT
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("peer FIN not received: state=%d", info.State)
				}
				time.Sleep(time.Millisecond)
			}
			transport, err := NewHelloTransport(helloTestPSK)
			if err != nil {
				t.Fatal(err)
			}
			wrapped := transport.Wrap(conn, conn.RemoteAddr().String()).(*helloConn)
			payload := make([]byte, len("reply"))
			if _, err = io.ReadFull(wrapped, payload); err != nil {
				t.Fatal(err)
			}
			if string(payload) != "reply" {
				t.Fatalf("response changed: %q", payload)
			}
			if !wrapped.observed.Load() {
				t.Fatal("negotiated capacity discarded after peer FIN")
			}
			learned, found := transport.capacities[wrapped.endpoint]
			cold, _ := transport.initialBudget(wrapped.endpoint)
			if !found || learned.bytes <= cold {
				t.Fatalf("capacity not learned: found=%v bytes=%d cold=%d", found, learned.bytes, cold)
			}
		})
	}
}
