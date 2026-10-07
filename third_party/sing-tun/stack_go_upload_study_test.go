//go:build upload_batch_study && linux && !android

package tun

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-snell/snellv6"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Run from the parent sing-box module, whose replace graph includes both local
// modules. No production dependency on sing-snell is added to sing-tun.
type uploadStudySocket struct {
	*net.TCPConn
	vector    N.VectorisedWriter
	writes    int64
	wireBytes int64
}

func (c *uploadStudySocket) Write(p []byte) (int, error) {
	c.writes++
	n, err := c.TCPConn.Write(p)
	c.wireBytes += int64(n)
	return n, err
}

func (c *uploadStudySocket) WriteVectorised(buffers []*buf.Buffer) error {
	c.writes++
	n := buf.LenMulti(buffers)
	err := c.vector.WriteVectorised(buffers)
	if err == nil {
		c.wireBytes += int64(n)
	}
	return err
}

func uploadStudyTCP(t testing.TB) (*uploadStudySocket, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	peer, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { peer.Close() })
	client.SetDeadline(time.Now().Add(2 * time.Minute))
	peer.SetDeadline(time.Now().Add(2 * time.Minute))
	vector, ok := bufio.CreateVectorisedWriter(client)
	if !ok {
		t.Fatal("TCP vector writer unavailable")
	}
	return &uploadStudySocket{TCPConn: client, vector: vector}, peer
}

func uploadStudyClient(t testing.TB, socket net.Conn, profileID int) net.Conn {
	t.Helper()
	client, err := snellv6.NewClient(snellv6.ClientOptions{PSK: []byte(fmt.Sprintf("public writepath fixture %d", profileID))})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := client.DialConn(socket, M.ParseSocksaddr("example.com:443"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

type uploadStudyAccepted struct {
	net.Conn
	complete N.CloseHandlerFunc
}
type uploadStudyHandler struct{ accepted chan uploadStudyAccepted }

func (h *uploadStudyHandler) NewConnectionEx(_ context.Context, conn net.Conn, _, _ M.Socksaddr, complete N.CloseHandlerFunc) {
	h.accepted <- uploadStudyAccepted{conn, complete}
}
func (h *uploadStudyHandler) NewPacketConnectionEx(_ context.Context, conn N.PacketConn, _, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	conn.Close()
}

func uploadStudySnellPair(t testing.TB, profileID int) (net.Conn, net.Conn, *uploadStudySocket) {
	t.Helper()
	socket, peer := uploadStudyTCP(t)
	handler := &uploadStudyHandler{accepted: make(chan uploadStudyAccepted, 1)}
	service, err := snellv6.NewService(snellv6.ServerOptions{PSK: []byte(fmt.Sprintf("public writepath fixture %d", profileID)), Handler: handler})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- service.NewConnection(context.Background(), peer, M.Socksaddr{}, nil) }()
	client := uploadStudyClient(t, socket, profileID)
	select {
	case server := <-handler.accepted:
		t.Cleanup(func() { client.Close(); peer.Close(); server.complete(nil); <-done; server.Close() })
		return client, server, socket
	case err := <-done:
		t.Fatalf("Snell handshake: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Snell handshake timeout")
	}
	return nil, nil, nil
}

func uploadStudySend(t testing.TB, source *GoConn, waiter N.VectorisedReadWaiter, writer N.ExtendedWriter, vector N.VectorisedWriter, size int, batch bool) (int, int) {
	t.Helper()
	maxCount, maxBytes := 0, 0
	for remaining := size; remaining > 0; {
		if batch {
			buffers, err := waiter.WaitReadBuffers()
			if err != nil {
				t.Fatal(err)
			}
			n := buf.LenMulti(buffers)
			maxCount, maxBytes = max(maxCount, len(buffers)), max(maxBytes, n)
			remaining -= n
			if len(buffers) == 1 {
				err = writer.WriteBuffer(buffers[0])
			} else {
				err = vector.WriteVectorised(buffers)
			}
			if err != nil {
				t.Fatal(err)
			}
		} else {
			buffer, err := source.WaitReadBuffer()
			if err != nil {
				t.Fatal(err)
			}
			maxCount, maxBytes = 1, max(maxBytes, buffer.Len())
			remaining -= buffer.Len()
			if err = writer.WriteBuffer(buffer); err != nil {
				t.Fatal(err)
			}
		}
		if remaining < 0 {
			t.Fatal("read beyond published data")
		}
	}
	return maxCount, maxBytes
}

func uploadStudyOrder() []bool {
	if os.Getenv("UPLOAD_STUDY_REVERSE") == "1" {
		return []bool{true, false}
	}
	return []bool{false, true}
}

// The source is prefilled once and its consumed offset reset per operation.
// This isolates a *ready backlog*: real GoConn reads, real Snell framing/crypto,
// and real TCP writes. It excludes TUN ingress, WAN delay and server decryption.
func BenchmarkGoUploadReadySnell(b *testing.B) {
	for _, profileID := range []int{2, 0, 1} { // Previously measured policies 0, 1, 2.
		for _, size := range []int{64, 1440, 0, -4, -8, -16} {
			for _, batch := range uploadStudyOrder() {
				b.Run(fmt.Sprintf("profile%d/size%d/batch%v", profileID, size, batch), func(b *testing.B) {
					socket, peer := uploadStudyTCP(b)
					var drained atomic.Int64
					done := make(chan struct{})
					go func() {
						defer close(done)
						data := make([]byte, 128<<10)
						for {
							n, err := peer.Read(data)
							drained.Add(int64(n))
							if err != nil {
								return
							}
						}
					}()
					b.Cleanup(func() { socket.Close(); peer.Close(); <-done })
					client := uploadStudyClient(b, socket, profileID)
					writer := bufio.NewExtendedWriter(client)
					vector, ok := bufio.CreateVectorisedWriter(client)
					if !ok {
						b.Fatal("Snell vector writer unavailable")
					}
					options := N.NewReadWaitOptions(nil, writer)
					options.IncreaseBuffer, options.BatchSize = true, 8
					probe := options.NewBuffer()
					capacity := probe.FreeLen()
					probe.Release()
					payloadSize := size
					if size <= 0 {
						payloadSize = max(1, -size) * capacity
					}
					payload := bytes.Repeat([]byte{0x45}, payloadSize)
					source := newGoReadWaitFixture(b, payload)
					waiter, _ := source.CreateVectorisedReadWaiter()
					waiter.InitializeReadWaiter(options)
					// Match the warmed framing state at the existing 512 kB switch.
					warm := make([]byte, 16384)
					for range 40 {
						if _, err := client.Write(warm); err != nil {
							b.Fatal(err)
						}
					}
					awaitDrain := func() {
						deadline := time.Now().Add(5 * time.Second)
						for drained.Load() < socket.wireBytes && time.Now().Before(deadline) {
							runtime.Gosched()
						}
						if drained.Load() != socket.wireBytes {
							b.Fatal("TCP peer failed to drain")
						}
					}
					awaitDrain()
					socket.writes = 0
					maxCount, maxBytes := 0, 0
					b.SetBytes(int64(payloadSize))
					b.ReportAllocs()
					b.ResetTimer()
					for range b.N {
						source.consumedTail.Store(1)
						count, retained := uploadStudySend(b, source, waiter, writer, vector, payloadSize, batch)
						maxCount, maxBytes = max(maxCount, count), max(maxBytes, retained)
					}
					awaitDrain()
					b.StopTimer()
					b.ReportMetric(float64(socket.writes)/float64(b.N), "writes/op")
					b.ReportMetric(float64(maxCount), "max-buffers")
					b.ReportMetric(float64(maxBytes), "max-ready-B")
					b.ReportMetric(float64(capacity), "buffer-cap-B")
				})
			}
		}
	}
}

// After bulk framing warmup, send one small message and wait for a one-byte
// application echo through the real Snell server and both TCP directions.
func TestGoUploadSmallRoundTrip(t *testing.T) {
	const rounds = 1000
	for _, profileID := range []int{2, 0, 1} {
		for _, size := range []int{64, 1440} {
			for _, batch := range uploadStudyOrder() {
				t.Run(fmt.Sprintf("profile%d/size%d/batch%v", profileID, size, batch), func(t *testing.T) {
					client, server, _ := uploadStudySnellPair(t, profileID)
					warmSize := 640 << 10
					done := make(chan error, 1)
					go func() {
						_, err := io.CopyN(io.Discard, server, int64(warmSize))
						if err == nil {
							_, err = server.Write([]byte{1})
						}
						message := make([]byte, size)
						for i := 0; i < rounds && err == nil; i++ {
							_, err = io.ReadFull(server, message)
							if err == nil {
								_, err = server.Write([]byte{1})
							}
						}
						done <- err
					}()
					if _, err := client.Write(make([]byte, warmSize)); err != nil {
						t.Fatal(err)
					}
					ack := make([]byte, 1)
					if _, err := io.ReadFull(client, ack); err != nil {
						t.Fatal(err)
					}
					writer := bufio.NewExtendedWriter(client)
					vector, _ := bufio.CreateVectorisedWriter(client)
					options := N.NewReadWaitOptions(nil, writer)
					options.IncreaseBuffer, options.BatchSize = true, 8
					source := newGoReadWaitFixture(t, bytes.Repeat([]byte{42}, size))
					waiter, _ := source.CreateVectorisedReadWaiter()
					waiter.InitializeReadWaiter(options)
					elapsed := make([]int64, rounds)
					for i := range elapsed {
						source.consumedTail.Store(1)
						start := time.Now()
						uploadStudySend(t, source, waiter, writer, vector, size, batch)
						if _, err := io.ReadFull(client, ack); err != nil {
							t.Fatal(err)
						}
						elapsed[i] = time.Since(start).Nanoseconds()
					}
					if err := <-done; err != nil {
						t.Fatal(err)
					}
					slices.Sort(elapsed)
					t.Logf("rtt-ns count=%d p50=%d p95=%d p99=%d", rounds, elapsed[rounds/2], elapsed[rounds*95/100], elapsed[rounds*99/100])
				})
			}
		}
	}
}

type uploadStudyScalar struct {
	net.Conn
	N.ReadWaiter
}

func TestGoKernelUploadBatchSnell(t *testing.T) {
	fixture := newKernelStackFixture(t, kernelStackConfig{mtu: 1500})
	for _, profileID := range []int{2, 0, 1} {
		for _, ipv6 := range []bool{false, true} {
			for _, batch := range []bool{false, true} {
				t.Run(fmt.Sprintf("profile%d/ipv6%v/batch%v", profileID, ipv6, batch), func(t *testing.T) {
					app, source := fixture.pair(t, ipv6)
					client, server, socket := uploadStudySnellPair(t, profileID)
					payload := kernelPayload(4<<20, 39)
					written := make(chan error, 1)
					go func() { _, err := app.Write(payload); written <- err }()
					copied := make(chan error, 1)
					go func() {
						var reader io.Reader = source
						if !batch {
							reader = &uploadStudyScalar{Conn: source, ReadWaiter: source}
						}
						n, err := bufio.Copy(client, reader)
						if err == nil && n != int64(len(payload)+64) {
							err = fmt.Errorf("copied %d bytes", n)
						}
						copied <- err
					}()
					got := make([]byte, len(payload))
					if _, err := io.ReadFull(server, got); err != nil || !bytes.Equal(got, payload) {
						t.Fatalf("decoded payload mismatch: %v", err)
					}
					if err := <-written; err != nil {
						t.Fatal(err)
					}
					// The same copy loop is now in bulk mode. A lone small message
					// must arrive while the application's write side remains open.
					message := bytes.Repeat([]byte{77}, 64)
					if _, err := app.Write(message); err != nil {
						t.Fatal(err)
					}
					if _, err := io.ReadFull(server, got[:64]); err != nil || !bytes.Equal(got[:64], message) {
						t.Fatalf("post-bulk message: %v", err)
					}
					app.CloseWrite()
					if err := <-copied; err != nil {
						t.Fatal(err)
					}
					t.Logf("socket writes=%d wire bytes=%d", socket.writes, socket.wireBytes)
				})
			}
		}
	}
}
