//go:build linux

package dialer

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-snell/snellv6"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/sys/unix"
)

var helloIntegrationPSK = []byte("public-snell-hello-integration-key")

type helloIntegrationHandler struct{}

func (helloIntegrationHandler) NewConnectionEx(_ context.Context, conn net.Conn, _, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	go func() {
		_, err := io.Copy(conn, conn)
		conn.Close()
		if onClose != nil {
			onClose(err)
		}
	}()
}

func (helloIntegrationHandler) NewPacketConnectionEx(_ context.Context, conn N.PacketConn, _, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	conn.Close()
	if onClose != nil {
		onClose(fmt.Errorf("unexpected UDP tunnel"))
	}
}

type helloIntegrationDecoded struct {
	net.Conn
	reader io.Reader
}

func (c *helloIntegrationDecoded) Read(p []byte) (int, error) { return c.reader.Read(p) }

func helloIntegrationServer(t *testing.T, network string) (M.Socksaddr, *atomic.Int32) {
	t.Helper()
	decoder, err := snellv6.NewHelloTransport(helloIntegrationPSK)
	if err != nil {
		t.Fatal(err)
	}
	server, err := snellv6.NewService(snellv6.ServerOptions{PSK: helloIntegrationPSK, Handler: helloIntegrationHandler{}})
	if err != nil {
		t.Fatal(err)
	}
	address := "127.0.0.1:0"
	if network == "tcp6" {
		address = "[::1]:0"
	}
	lc := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var socketErr error
		err := raw.Control(func(fd uintptr) { socketErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_FASTOPEN, 128) })
		if err != nil {
			return err
		}
		return socketErr
	}}
	listener, err := lc.Listen(context.Background(), network, address)
	if err != nil {
		t.Fatal(err)
	}
	var accepted atomic.Int32
	var access sync.Mutex
	var connections []net.Conn
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			access.Lock()
			connections = append(connections, conn)
			access.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				prefix, err := decoder.DecodeHello(conn)
				if err != nil {
					conn.Close()
					return
				}
				decoded := &helloIntegrationDecoded{Conn: conn, reader: io.MultiReader(bytes.NewReader(prefix), conn)}
				if err = server.NewConnection(context.Background(), decoded, M.Socksaddr{}, func(error) { conn.Close() }); err != nil {
					conn.Close()
				}
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		access.Lock()
		for _, conn := range connections {
			conn.Close()
		}
		access.Unlock()
		workers.Wait()
	})
	return M.ParseSocksaddr(listener.Addr().String()), &accepted
}

type helloIntegrationDialer struct {
	N.Dialer
	last  *slowOpenConn
	count int
}

func (d *helloIntegrationDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	conn, err := d.Dialer.DialContext(ctx, network, destination)
	if err == nil {
		d.last = conn.(*slowOpenConn)
		d.count++
	}
	return conn, err
}

// Exercise the actual SFA default dialer and delayed first write, with a real
// Snell client/server. This checks I/O and cache lifecycle, not SYN acceptance:
// loopback timing cannot substitute for a packet capture on the affected path.
func TestSnellHelloDeferredTFO(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		for _, reuse := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/reuse=%v", network, reuse), func(t *testing.T) {
				endpoint, accepted := helloIntegrationServer(t, network)
				var sockets atomic.Int32
				ctx := tfoContext(t, adapter.NetworkOptions{}, func(string, string, syscall.RawConn) error {
					sockets.Add(1)
					return nil
				})
				base, err := NewDefault(ctx, tfoOptions(t, `{"tcp_fast_open":true,"connect_timeout":"2s"}`))
				if err != nil {
					t.Fatal(err)
				}
				dialer := &helloIntegrationDialer{Dialer: base}
				transport, err := snellv6.NewHelloTransport(helloIntegrationPSK)
				if err != nil {
					t.Fatal(err)
				}
				frames := make(chan snellv6.HelloFrameInfo, 4)
				transport.OnFirstFrame = func(info snellv6.HelloFrameInfo) { frames <- info }
				client, err := snellv6.NewClient(snellv6.ClientOptions{PSK: helloIntegrationPSK, Reuse: reuse, Server: endpoint, Dialer: transport.WrapDialer(dialer)})
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				for index, size := range []int{128, 2048, 128} {
					if index == 2 {
						transport.Reset()
						client.Reset()
					}
					before := sockets.Load()
					conn, err := client.DialContext(ctx, M.ParseSocksaddr("example.test:443"))
					if err != nil {
						t.Fatal(err)
					}
					defer conn.Close()
					newPhysical := !reuse || index != 1
					if sockets.Load() != before {
						t.Fatal("opened a socket before application bytes")
					}
					if newPhysical && (dialer.last.conn.Load() != nil || dialer.last.DialDestination().String() != endpoint.String()) {
						t.Fatal("deferred dial lost its destination or opened early")
					}
					want := bytes.Repeat([]byte{byte(index + 1)}, size)
					if n, err := conn.Write(want); err != nil || n != len(want) {
						t.Fatal(n, err)
					}
					conn.SetDeadline(time.Now().Add(3 * time.Second))
					got := make([]byte, len(want))
					if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, want) {
						t.Fatal("decrypted response differs", err)
					}
					if newPhysical {
						if sockets.Load() != before+1 {
							t.Fatal("extra physical socket", before, sockets.Load())
						}
						info := <-frames
						expectedSource := "cold_estimate"
						expectedColdBudget := 496
						if network == "tcp6" {
							expectedSource, expectedColdBudget = "cold_ipv6_estimate", 1180
						}
						if index == 1 {
							expectedSource = "observed_peer"
						}
						if info.BudgetSource != expectedSource || info.WireBytes > info.Budget {
							t.Fatal(info, expectedSource)
						}
						if index != 1 && (info.Budget != expectedColdBudget || info.OriginalBytes != info.InitialWriteBytes) {
							t.Fatal("cold compact request did not fit", info)
						}
						raw, err := dialer.last.conn.Load().SyscallConn()
						if err != nil {
							t.Fatal(err)
						}
						var fastOpen int
						var socketErr error
						if err := raw.Control(func(fd uintptr) {
							fastOpen, socketErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_FASTOPEN_CONNECT)
						}); err != nil {
							t.Fatal(err)
						}
						if socketErr != nil || fastOpen != 1 {
							t.Fatal("TFO dial was bypassed", fastOpen, socketErr)
						}
						t.Logf("request=%d budget=%d source=%s wire=%d original=%d initial=%d", index, info.Budget, info.BudgetSource, info.WireBytes, info.OriginalBytes, info.InitialWriteBytes)
					} else if len(frames) != 0 || sockets.Load() != before {
						t.Fatal("sequential reuse reframed or reopened the transport")
					}
					if err = conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
						t.Fatal(err)
					}
					if _, err = io.Copy(io.Discard, conn); err != nil {
						t.Fatal(err)
					}
					if err = conn.Close(); err != nil {
						t.Fatal(err)
					}
				}
				wantPhysical := int32(3)
				if reuse {
					wantPhysical = 2
				}
				if sockets.Load() != wantPhysical || accepted.Load() != wantPhysical || int32(dialer.count) != wantPhysical || len(frames) != 0 {
					t.Fatal("physical socket/frame totals", sockets.Load(), accepted.Load(), dialer.count, len(frames))
				}
			})
		}
	}
}
