package snell

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing-snell/snellv6"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

var helloLifecyclePSK = []byte("public-hello-outbound-lifecycle-key")

type helloLifecycleEcho struct{ N.UDPConnectionHandlerEx }

func (helloLifecycleEcho) NewConnectionEx(_ context.Context, conn net.Conn, _, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	go func() {
		_, err := io.Copy(conn, conn)
		conn.Close()
		if onClose != nil {
			onClose(err)
		}
	}()
}

type helloLifecycleDecoded struct {
	net.Conn
	reader io.Reader
}

func (c *helloLifecycleDecoded) Read(p []byte) (int, error) { return c.reader.Read(p) }

func helloLifecycleServer(t *testing.T, family string) (M.Socksaddr, *atomic.Int32) {
	t.Helper()
	address := "127.0.0.1:0"
	if family == "tcp6" {
		address = "[::1]:0"
	}
	listener, err := net.Listen(family, address)
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := snellv6.NewHelloTransport(helloLifecyclePSK)
	if err != nil {
		t.Fatal(err)
	}
	server, err := snellv6.NewService(snellv6.ServerOptions{PSK: helloLifecyclePSK, Handler: helloLifecycleEcho{}})
	if err != nil {
		t.Fatal(err)
	}
	var accepted atomic.Int32
	var mu sync.Mutex
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
			mu.Lock()
			connections = append(connections, conn)
			mu.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				prefix, err := decoder.DecodeHello(conn)
				if err != nil {
					conn.Close()
					return
				}
				decoded := &helloLifecycleDecoded{conn, io.MultiReader(bytes.NewReader(prefix), conn)}
				if err := server.NewConnection(context.Background(), decoded, M.Socksaddr{}, func(error) { conn.Close() }); err != nil {
					conn.Close()
				}
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		mu.Lock()
		for _, conn := range connections {
			conn.Close()
		}
		mu.Unlock()
		workers.Wait()
	})
	return M.ParseSocksaddr(listener.Addr().String()), &accepted
}

func helloLifecycleOutbound(t *testing.T, family string, tfo, reuse bool) (*Outbound, *route.ConnectionManager, *adapter.Scope, context.Context, <-chan snellv6.HelloFrameInfo, *atomic.Int32) {
	t.Helper()
	endpoint, accepted := helloLifecycleServer(t, family)
	ctx, cancel := context.WithTimeout(service.ContextWithDefaultRegistry(context.Background()), 6*time.Second)
	t.Cleanup(cancel)
	manager := route.NewConnectionManager(logger.NOP())
	service.MustRegister[adapter.ConnectionManager](ctx, manager)
	opts := option.SnellOutboundOptions{Version: 6, AbstractSnellOutboundOptions: option.AbstractSnellOutboundOptions{
		ServerOptions: option.ServerOptions{Server: endpoint.Addr.String(), ServerPort: endpoint.Port},
		PSK:           string(helloLifecyclePSK), Reuse: reuse, HelloFraming: true,
	}}
	opts.TCPFastOpen = tfo
	created, err := NewOutbound(ctx, nil, logger.NOP(), "hello-lifecycle", opts)
	if err != nil {
		t.Fatal(err)
	}
	node := created.(*Outbound)
	frames := make(chan snellv6.HelloFrameInfo, 16)
	node.hello.OnFirstFrame = func(info snellv6.HelloFrameInfo) { frames <- info }
	scope := adapter.NewScope(ctx, logger.NOP())
	if err := node.Start(adapter.StartStateInitialize, scope); err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(adapter.StartStateInitialize, scope); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { scope.Close() })
	return node, manager, scope, ctx, frames, accepted
}

func helloLifecycleExchange(t *testing.T, node *Outbound, ctx context.Context, finish bool) net.Conn {
	t.Helper()
	conn, err := node.DialContext(ctx, "tcp", M.ParseSocksaddr("example.test:443"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	want := bytes.Repeat([]byte{0x67}, 128)
	if _, err := conn.Write(want); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, want) {
		t.Fatal("echo differs", err)
	}
	if finish {
		if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, conn); err != nil {
			t.Fatal(err)
		}
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return conn
}

// Exercise the real outbound constructor, physical-connection manager, pool,
// interface-update listener and lifecycle scope together. Loopback is used;
// Android OS notification delivery and native SYN acceptance are not asserted.
func TestSnellHelloOutboundLifecycle(t *testing.T) {
	for _, family := range []string{"tcp4", "tcp6"} {
		for _, tfo := range []bool{false, true} {
			for _, reuse := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/tfo=%v/reuse=%v", family, tfo, reuse), func(t *testing.T) {
					node, manager, scope, ctx, frames, accepted := helloLifecycleOutbound(t, family, tfo, reuse)
					physical := int32(0)
					exchange := func(fresh, cold, finish bool) net.Conn {
						conn := helloLifecycleExchange(t, node, ctx, finish)
						if fresh {
							physical++
							select {
							case info := <-frames:
								want := "negotiated"
								if tfo {
									want = "observed_peer"
									if cold {
										want = "cold_estimate"
										if family == "tcp6" {
											want = "cold_ipv6_estimate"
										}
									}
								}
								if info.BudgetSource != want {
									t.Fatal("wrong capacity source", info, want)
								}
							case <-ctx.Done():
								t.Fatal("missing initial carrier")
							}
						} else if len(frames) != 0 {
							t.Fatal("reused connection reframed")
						}
						if accepted.Load() != physical {
							t.Fatal("extra physical connection", accepted.Load(), physical)
						}
						return conn
					}
					exchange(true, true, true)
					exchange(!reuse, false, true)
					// Same ordering as NetworkManager.ResetNetwork: close tracked
					// physical sockets before notifying the outbound.
					manager.CloseAll()
					node.InterfaceUpdated(ctx)
					if manager.Count() != 0 {
						t.Fatal("network reset retained sockets")
					}
					exchange(true, true, true)
					node.CloseIdleConnections()
					if manager.Count() != 0 {
						t.Fatal("idle close retained sockets")
					}
					exchange(true, false, true)
					node.SetKeepIdleConnections(false)
					exchange(true, false, true)
					exchange(true, false, true)
					if manager.Count() != 0 {
						t.Fatal("inactive outbound retained sockets")
					}
					node.SetKeepIdleConnections(true)
					active := exchange(true, false, false)
					readResult := make(chan error, 1)
					go func() { var b [1]byte; _, err := active.Read(b[:]); readResult <- err }()
					manager.CloseAll()
					node.InterfaceUpdated(ctx)
					select {
					case err := <-readResult:
						if err == nil {
							t.Fatal("read survived physical network reset")
						}
					case <-ctx.Done():
						t.Fatal("network reset did not release pending read")
					}
					active.Close()
					exchange(true, true, true)
					if err := scope.Close(); err != nil {
						t.Fatal(err)
					}
					if manager.Count() != 0 {
						t.Fatal("service close retained sockets")
					}
					if conn, err := node.DialContext(ctx, "tcp", M.ParseSocksaddr("example.test:443")); err == nil {
						conn.Close()
						t.Fatal("dial accepted after service close")
					}
					t.Logf("physical=%d; reuse, idle release, network reset, pending read and service close verified", physical)
				})
			}
		}
	}
}

func TestSnellHelloOutboundResetBeforeFirstWrite(t *testing.T) {
	for _, reuse := range []bool{false, true} {
		t.Run(fmt.Sprintf("reuse=%v", reuse), func(t *testing.T) {
			node, manager, _, ctx, frames, accepted := helloLifecycleOutbound(t, "tcp4", true, reuse)
			conn, err := node.DialContext(ctx, "tcp", M.ParseSocksaddr("example.test:443"))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if manager.Count() != 1 {
				t.Fatal("deferred connection was not tracked")
			}
			manager.CloseAll()
			node.InterfaceUpdated(ctx)
			if _, err := conn.Write([]byte("must never open after reset")); err == nil {
				t.Fatal("first write survived reset")
			}
			if accepted.Load() != 0 || len(frames) != 0 || manager.Count() != 0 {
				t.Fatal("reset deferred connection created a socket or carrier")
			}
			helloLifecycleExchange(t, node, ctx, true)
			if info := <-frames; info.BudgetSource != "cold_estimate" {
				t.Fatal("replacement was not cold", info)
			}
		})
	}
}
