//go:build (linux && !android) || (darwin && !ios) || windows

package tun

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestGoKernelHandshake(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		for _, action := range []string{"accept", "reject", "close"} {
			t.Run(fmt.Sprintf("ipv6=%v/action=%s", ipv6, action), func(test *testing.T) {
				test.Parallel()
				observed := make(chan *GoConn, 1)
				var observe sync.Once
				release := make(chan struct{})
				unblock := sync.OnceFunc(func() { close(release) })
				fixture := newKernelStackFixture(test, kernelStackConfig{mtu: 1500, dialer: net.Dialer{Timeout: 5 * time.Second}, handshake: func(conn *GoConn) error {
					observe.Do(func() { observed <- conn })
					test.Cleanup(func() { conn.Close() })
					<-release
					switch action {
					case "reject":
						return conn.HandshakeFailure(kernelConnectionRefused)
					case "close":
						return conn.Close()
					default:
						return conn.HandshakeSuccess()
					}
				}})
				test.Cleanup(unblock)
				port := uint16(20000 + fixture.port.Add(1))
				fixture.access.Lock()
				fixture.tcp[port] = make(chan kernelAccept, 8)
				fixture.access.Unlock()
				type dialResult struct {
					conn net.Conn
					err  error
				}
				dialed := make(chan dialResult, 1)
				go func() {
					conn, err := fixture.dialer.Dial("tcp", fixture.address(ipv6, port))
					dialed <- dialResult{conn: conn, err: err}
				}()
				var server *GoConn
				select {
				case server = <-observed:
				case <-time.After(time.Second):
					test.Fatal("connection did not reach the application")
				}
				select {
				case result := <-dialed:
					if result.conn != nil {
						result.conn.Close()
					}
					test.Fatalf("dial completed before application decision: %v", result.err)
				case <-time.After(80 * time.Millisecond):
				}
				unblock()
				select {
				case result := <-dialed:
					if action != "accept" {
						if result.conn != nil {
							result.conn.Close()
						}
						if !errors.Is(result.err, kernelConnectionRefused) {
							test.Fatalf("application %s: %v", action, result.err)
						}
						return
					}
					if result.err != nil {
						test.Fatal(result.err)
					}
					defer result.conn.Close()
					result.conn.SetDeadline(time.Now().Add(3 * time.Second))
					err := kernelTransfer(server, result.conn, kernelPayload(32769, 157), true)
					if err != nil {
						test.Fatal("accepted stream:", err)
					}
				case <-time.After(6 * time.Second):
					test.Fatal("application decision did not complete the dial")
				}
			})
		}
	}
}

func TestGoKernelHalfClose(t *testing.T) {
	fixture := newKernelStackFixture(t, kernelStackConfig{mtu: 1500})
	for _, ipv6 := range []bool{false, true} {
		for _, splice := range []bool{false, true} {
			t.Run(fmt.Sprintf("ipv6=%v/splice=%v", ipv6, splice), func(test *testing.T) {
				test.Parallel()
				var client, server net.Conn
				if splice {
					client, server, _, _ = fixture.splicePair(test, ipv6)
				} else {
					client, server = fixture.pair(test, ipv6)
				}
				err := kernelTransfer(client, server, kernelPayload(256<<10, 163), false)
				if err != nil {
					test.Fatal("request and FIN:", err)
				}
				err = kernelTransfer(server, client, kernelPayload(2<<20, 167), false)
				if err != nil {
					test.Fatal("response after peer FIN:", err)
				}
			})
		}
		t.Run(fmt.Sprintf("ipv6=%v/close_read", ipv6), func(test *testing.T) {
			test.Parallel()
			client, server := fixture.pair(test, ipv6)
			completed := make(chan kernelIOResult, 1)
			go func() {
				n, err := server.Read(make([]byte, 1))
				completed <- kernelIOResult{n: n, err: err}
			}()
			select {
			case result := <-completed:
				test.Fatalf("read did not wait: %+v", result)
			case <-time.After(40 * time.Millisecond):
			}
			err := server.CloseRead()
			if err != nil {
				test.Fatal(err)
			}
			select {
			case result := <-completed:
				if result.n != 0 || result.err != io.EOF {
					test.Fatalf("CloseRead: %+v", result)
				}
			case <-time.After(time.Second):
				test.Fatal("CloseRead did not wake reader")
			}
			uploaded := make(chan error, 1)
			go func() {
				_, writeErr := client.Write(kernelPayload(1<<20, 173))
				if writeErr == nil {
					writeErr = client.CloseWrite()
				}
				uploaded <- writeErr
			}()
			err = kernelTransfer(server, client, kernelPayload(256<<10, 179), true)
			if err != nil {
				test.Fatal("write after CloseRead:", err)
			}
			select {
			case err = <-uploaded:
				if err != nil {
					test.Fatal("peer upload after CloseRead:", err)
				}
			case <-time.After(time.Second):
				test.Fatal("discarded input blocked the peer")
			}
		})
		t.Run(fmt.Sprintf("ipv6=%v/upstream_reset", ipv6), func(test *testing.T) {
			test.Parallel()
			client, upstream, _, _ := fixture.splicePair(test, ipv6)
			marker := kernelPayload(1024, 181)
			_, err := upstream.Write(marker)
			if err != nil {
				test.Fatal(err)
			}
			data := make([]byte, len(marker))
			_, err = io.ReadFull(client, data)
			if err != nil || !bytes.Equal(data, marker) {
				test.Fatal("upstream data before reset:", err)
			}
			upstream.SetLinger(0)
			upstream.Close()
			client.SetReadDeadline(time.Now().Add(time.Second))
			_, err = client.Read(data[:1])
			if !errors.Is(err, kernelConnectionReset) {
				test.Fatalf("upstream reset: %v", err)
			}
		})
	}
}
