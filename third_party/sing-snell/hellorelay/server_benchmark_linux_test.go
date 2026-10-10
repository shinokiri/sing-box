//go:build linux

package hellorelay

import (
	"bytes"
	"io"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-snell/snellv6"
	M "github.com/sagernet/sing/common/metadata"
)

// These are loopback cost measurements, not public-network throughput claims.
// Process CPU includes the client and synthetic upstream in every variant.
func receiverCostCPU(b *testing.B) float64 {
	b.Helper()
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		b.Fatal(err)
	}
	return float64(usage.Utime.Sec+usage.Stime.Sec)*1e6 + float64(usage.Utime.Usec+usage.Stime.Usec)
}

func receiverCostFixture(b *testing.B) (framed, original []byte) {
	b.Helper()
	raw := new(memoryConn)
	client, err := snellv6.NewClient(snellv6.ClientOptions{PSK: testKey, Mode: snellv6.ModeDefault})
	if err != nil {
		b.Fatal(err)
	}
	defer client.Close()
	conn := client.DialEarlyConn(raw, M.ParseSocksaddr("example.com:443"))
	if _, err = conn.Write(bytes.Repeat([]byte{0x71}, 512)); err != nil {
		b.Fatal(err)
	}
	original = append([]byte(nil), raw.Bytes()...)
	transport, err := snellv6.NewHelloTransportWithOptions(testKey, snellv6.HelloTransportOptions{InitialSYNDataLimit: 4096})
	if err != nil {
		b.Fatal(err)
	}
	wire := new(memoryConn)
	if _, err = transport.Wrap(wire, "127.0.0.1:12346").Write(original); err != nil {
		b.Fatal(err)
	}
	return append([]byte(nil), wire.Bytes()...), original
}

func receiverCostEndpoint(b *testing.B, prefix, bulk []byte) string {
	b.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	var handlers sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			handlers.Add(1)
			go func() {
				defer handlers.Done()
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(30 * time.Second))
				first := make([]byte, len(prefix))
				if _, err := io.ReadFull(conn, first); err != nil || !bytes.Equal(first, prefix) {
					b.Error("prefix differs", err)
					return
				}
				if _, err := conn.Write([]byte{0xac}); err != nil {
					b.Error(err)
					return
				}
				var buffer []byte
				var command [1]byte
				for {
					if _, err := io.ReadFull(conn, command[:]); err != nil {
						if err != io.EOF {
							b.Error(err)
						}
						return
					}
					switch command[0] {
					case 1:
						if buffer == nil {
							buffer = make([]byte, len(bulk))
						}
						if _, err := io.ReadFull(conn, buffer); err != nil || !bytes.Equal(buffer, bulk) {
							b.Error("bulk differs", err)
							return
						}
						if _, err := conn.Write([]byte{0xac}); err != nil {
							b.Error(err)
							return
						}
					case 2:
						if _, err := conn.Write(bulk); err != nil {
							b.Error(err)
							return
						}
					default:
						b.Error("invalid benchmark command")
						return
					}
				}
			}()
		}
	}()
	b.Cleanup(func() {
		listener.Close()
		<-done
		handlers.Wait()
	})
	return listener.Addr().String()
}

func BenchmarkHelloReceiverCost(b *testing.B) {
	framed, original := receiverCostFixture(b)
	bulk := bytes.Repeat([]byte{0x3d}, 1<<20)
	for _, mode := range []string{"direct", "pass", "decode"} {
		for _, action := range []string{"FirstResponse", "UploadMiB", "DownloadMiB"} {
			b.Run(mode+"/"+action, func(b *testing.B) {
				sendPrefix, targetPrefix := original, original
				if mode != "direct" {
					sendPrefix = framed
				}
				if mode == "pass" {
					targetPrefix = framed
				}
				address := receiverCostEndpoint(b, targetPrefix, bulk)
				if mode != "direct" {
					opts := Options{Mode: Mode(mode), Upstream: address}
					if mode == "decode" {
						opts.PSK = testKey
					}
					s, err := New(opts)
					if err != nil {
						b.Fatal(err)
					}
					listener, err := s.Listen("127.0.0.1:0")
					if err != nil {
						b.Fatal(err)
					}
					address = listener.Addr().String()
					done := make(chan error, 1)
					go func() { done <- s.Serve(listener) }()
					b.Cleanup(func() {
						s.Close()
						if err := <-done; err != nil {
							b.Error(err)
						}
					})
				}
				dial := func() net.Conn {
					conn, err := net.DialTimeout("tcp4", address, time.Second)
					if err != nil {
						b.Fatal(err)
					}
					conn.SetDeadline(time.Now().Add(30 * time.Second))
					if _, err := conn.Write(sendPrefix); err != nil {
						conn.Close()
						b.Fatal(err)
					}
					var reply [1]byte
					if _, err := io.ReadFull(conn, reply[:]); err != nil || reply[0] != 0xac {
						conn.Close()
						b.Fatal("first reply", err)
					}
					return conn
				}
				b.ReportAllocs()
				if action == "FirstResponse" {
					cpu := receiverCostCPU(b)
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						dial().Close()
					}
					b.StopTimer()
					b.ReportMetric((receiverCostCPU(b)-cpu)/float64(b.N), "cpu-us/op")
					return
				}
				conn := dial()
				defer conn.Close()
				buffer := make([]byte, len(bulk))
				command, reply := []byte{1}, []byte{0}
				if action == "DownloadMiB" {
					command[0] = 2
				}
				b.SetBytes(int64(len(bulk)))
				cpu := receiverCostCPU(b)
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, err := conn.Write(command); err != nil {
						b.Fatal(err)
					}
					if command[0] == 1 {
						if _, err := conn.Write(bulk); err != nil {
							b.Fatal(err)
						}
						if _, err := io.ReadFull(conn, reply); err != nil || reply[0] != 0xac {
							b.Fatal("bulk reply", err)
						}
					} else if _, err := io.ReadFull(conn, buffer); err != nil || !bytes.Equal(buffer, bulk) {
						b.Fatal("download differs", err)
					}
				}
				b.StopTimer()
				b.ReportMetric((receiverCostCPU(b)-cpu)/float64(b.N), "cpu-us/op")
			})
		}
	}
}
