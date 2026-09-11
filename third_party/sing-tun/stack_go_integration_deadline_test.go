//go:build (linux && !android) || (darwin && !ios) || windows

package tun

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

type kernelIOResult struct {
	n   int
	err error
}

func TestGoKernelDeadline(t *testing.T) {
	fixture := newKernelStackFixture(t, kernelStackConfig{mtu: 9000})
	for _, ipv6 := range []bool{false, true} {
		for _, operation := range []string{"read", "wait_read", "write"} {
			for _, change := range []string{"advance", "extend", "clear", "close"} {
				t.Run(fmt.Sprintf("ipv6=%v/operation=%s/change=%s", ipv6, operation, change), func(test *testing.T) {
					test.Parallel()
					client, server := fixture.pair(test, ipv6)
					writing := operation == "write"
					payload := []byte{0x71}
					setDeadline := server.SetReadDeadline
					if writing {
						payload = kernelPayload(8<<20, 151)
						setDeadline = server.SetWriteDeadline
						err := client.SetReadBuffer(4096)
						if err != nil {
							test.Fatal(err)
						}
					}
					var waiter N.ReadWaiter
					if operation == "wait_read" {
						var created bool
						waiter, created = bufio.CreateReadWaiter(server)
						if !created {
							test.Fatal("missing read waiter")
						}
						waiter.InitializeReadWaiter(N.ReadWaitOptions{FrontHeadroom: 91, RearHeadroom: 73})
					}
					read := func() kernelIOResult {
						if waiter != nil {
							buffer, err := waiter.WaitReadBuffer()
							result := kernelIOResult{err: err}
							if buffer != nil {
								result.n = buffer.Len()
								if !bytes.Equal(buffer.Bytes(), payload) {
									result.err = E.New("read waiter payload mismatch")
								}
								buffer.ExtendHeader(91)
								buffer.Extend(73)
								buffer.Release()
							}
							return result
						}
						data := make([]byte, len(payload))
						n, err := io.ReadFull(server, data)
						if err == nil && !bytes.Equal(data, payload) {
							err = E.New("read payload mismatch")
						}
						return kernelIOResult{n: n, err: err}
					}
					original := time.Now().Add(300 * time.Millisecond)
					if change == "advance" || change == "close" {
						original = time.Now().Add(4 * time.Second)
					}
					setDeadline(original)
					completed := make(chan kernelIOResult, 1)
					go func() {
						if writing {
							n, err := server.Write(payload)
							completed <- kernelIOResult{n: n, err: err}
						} else {
							completed <- read()
						}
					}()
					select {
					case result := <-completed:
						test.Fatalf("I/O did not wait: %+v", result)
					case <-time.After(40 * time.Millisecond):
					}
					switch change {
					case "advance":
						setDeadline(time.Now())
					case "extend":
						setDeadline(time.Now().Add(4 * time.Second))
					case "clear":
						setDeadline(time.Time{})
					case "close":
						server.Close()
					}
					accepted := 0
					if change == "advance" || change == "close" {
						select {
						case result := <-completed:
							accepted = result.n
							if accepted < 0 || accepted >= len(payload) {
								test.Fatalf("blocked I/O accepted %d/%d bytes", accepted, len(payload))
							}
							if change == "advance" && !errors.Is(result.err, os.ErrDeadlineExceeded) {
								test.Fatalf("updated deadline: %v", result.err)
							}
							if change == "close" && (!E.IsClosed(result.err) || E.IsTimeout(result.err)) {
								test.Fatalf("close pending I/O: %v", result.err)
							}
						case <-time.After(time.Second):
							test.Fatal("pending I/O did not react to deadline/close")
						}
						if change == "close" {
							return
						}
						setDeadline(time.Now().Add(4 * time.Second))
						go func() {
							if writing {
								n, err := server.Write(payload[accepted:])
								completed <- kernelIOResult{n: n + accepted, err: err}
							} else {
								completed <- read()
							}
						}()
					} else {
						select {
						case result := <-completed:
							test.Fatalf("old deadline still affected I/O: %+v", result)
						case <-time.After(time.Until(original.Add(40 * time.Millisecond))):
						}
					}
					if writing {
						client.SetReadBuffer(4 << 20)
						data := make([]byte, len(payload))
						n, err := io.ReadFull(client, data)
						if err != nil || !bytes.Equal(data, payload) {
							select {
							case result := <-completed:
								test.Logf("writer after deadline change: accepted=%d: %v", result.n, result.err)
							default:
							}
							test.Fatalf("write after deadline change: received=%d/%d accepted_before_change=%d: %v", n, len(payload), accepted, err)
						}
					} else {
						_, err := client.Write(payload)
						if err != nil {
							test.Fatal(err)
						}
					}
					select {
					case result := <-completed:
						if result.err != nil || result.n != len(payload) {
							test.Fatalf("completed I/O: %+v", result)
						}
					case <-time.After(time.Second):
						test.Fatal("I/O remained blocked after peer resumed")
					}
				})
			}
		}
	}
}
