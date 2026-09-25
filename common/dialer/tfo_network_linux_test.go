//go:build linux

package dialer

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"

	"golang.org/x/sys/unix"
)

func networkTFOListener(t *testing.T, family string) M.Socksaddr {
	t.Helper()
	address := "127.0.0.1:0"
	if family == "tcp6" {
		address = "[::1]:0"
	}
	listener, err := net.Listen(family, address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				var payload [4]byte
				if _, err := io.ReadFull(conn, payload[:]); err == nil {
					conn.Write(payload[:])
				}
			}()
		}
	}()
	return M.ParseSocksaddr(listener.Addr().String())
}

func networkTFOExchange(conn net.Conn, want bool) error {
	if _, err := conn.Write([]byte("ping")); err != nil {
		return err
	}
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	var response [4]byte
	if _, err := io.ReadFull(conn, response[:]); err != nil {
		return err
	}
	if string(response[:]) != "ping" {
		return fmt.Errorf("unexpected response: %q", response)
	}
	var underlying any = conn
	if wrapped, ok := underlying.(interface{ Upstream() any }); ok {
		underlying = wrapped.Upstream()
	}
	tcp, ok := underlying.(*net.TCPConn)
	if !ok {
		return fmt.Errorf("unexpected connection: %T", underlying)
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		return err
	}
	var value int
	var socketErr error
	if err = raw.Control(func(fd uintptr) {
		value, socketErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_FASTOPEN_CONNECT)
	}); err != nil {
		return err
	}
	if socketErr != nil {
		return socketErr
	}
	if (value != 0) != want {
		return fmt.Errorf("TCP_FASTOPEN_CONNECT=%d, want enabled=%v", value, want)
	}
	return nil
}

func publishTFOPolicy(manager *tfoNetworkManager) {
	manager.tfoState.Store(adapter.NewNetworkTFOState(manager.loopback.Index, manager.interfaces))
}

func TestPlatformTFONetworkPolicy(t *testing.T) {
	for _, family := range []string{"tcp4", "tcp6"} {
		for _, configured := range []bool{false, true} {
			for _, interfaceEntry := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/configured=%v/interface=%v", family, configured, interfaceEntry), func(t *testing.T) {
					destination := networkTFOListener(t, family)
					var protected atomic.Int32
					ctx := tfoContext(t, adapter.NetworkOptions{}, func(string, string, syscall.RawConn) error {
						protected.Add(1)
						return nil
					})
					manager := service.FromContext[adapter.NetworkManager](ctx).(*tfoNetworkManager)
					dialer, err := NewDefault(ctx, tfoOptions(t, fmt.Sprintf(`{"tcp_fast_open":%v}`, configured)))
					if err != nil {
						t.Fatal(err)
					}
					dialer.androidTFO = true
					for _, tc := range []struct {
						name string
						kind C.InterfaceType
						known bool
						want bool
					}{
						{"wifi", C.InterfaceTypeWIFI, true, true},
						{"sim1", C.InterfaceTypeCellular, true, false},
						{"sim2", C.InterfaceTypeCellular, true, false},
						{"wifi-again", C.InterfaceTypeWIFI, true, true},
						{"ethernet", C.InterfaceTypeEthernet, true, true},
						{"other-physical", C.InterfaceTypeOther, true, true},
						{"missing-policy", C.InterfaceTypeWIFI, false, false},
						{"invalid-type", C.InterfaceType(255), true, false},
					} {
						t.Run(tc.name, func(t *testing.T) {
							manager.interfaces = []adapter.NetworkInterface{
								{Interface: *manager.loopback, Type: tc.kind},
								{Interface: control.Interface{Name: "unused-cellular", Index: 12345}, Type: C.InterfaceTypeCellular},
							}
							publishTFOPolicy(manager)
							if !tc.known {
								manager.tfoState.Store(nil)
							}
							beforeProtect := protected.Load()
							var conn net.Conn
							if interfaceEntry {
								strategy := C.NetworkStrategyDefault
								conn, err = dialer.DialParallelInterface(ctx, "tcp", destination, &strategy, nil, nil, 0)
							} else {
								conn, err = dialer.DialContext(ctx, "tcp", destination)
							}
							if err != nil {
								t.Fatal(err)
							}
							defer conn.Close()
							reads := manager.interfaceReads.Load()
							if err := networkTFOExchange(conn, configured && tc.want); err != nil {
								t.Fatal(err)
							}
							if protected.Load()-beforeProtect != 1 {
								t.Fatal("VPN protect callback was changed")
							}
							if manager.interfaceReads.Load() != reads {
								t.Fatal("first write enumerated network interfaces")
							}
							if dialer.dialer4.DisableTFO != !configured || dialer.dialer6.DisableTFO != !configured {
								t.Fatal("network policy changed the configured shared dialer")
							}
						})
					}
				})
			}
		}
	}
}

func TestPlatformTFONetworkChangesBeforeWrite(t *testing.T) {
	for _, family := range []string{"tcp4", "tcp6"} {
		for _, toCellular := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/to-cellular=%v", family, toCellular), func(t *testing.T) {
				destination := networkTFOListener(t, family)
				ctx := tfoContext(t, adapter.NetworkOptions{}, nil)
				manager := service.FromContext[adapter.NetworkManager](ctx).(*tfoNetworkManager)
				before, after := C.InterfaceTypeCellular, C.InterfaceTypeWIFI
				if toCellular {
					before, after = after, before
				}
				manager.interfaces[0].Type = before
				publishTFOPolicy(manager)
				dialer, err := NewDefault(ctx, tfoOptions(t, `{"tcp_fast_open":true}`))
				if err != nil {
					t.Fatal(err)
				}
				dialer.androidTFO = true
				conn, err := dialer.DialContext(ctx, "tcp", destination)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				manager.interfaces[0].Type = after
				publishTFOPolicy(manager)
				if err := networkTFOExchange(conn, !toCellular); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestPlatformTFONetworkExplicitBinding(t *testing.T) {
	for _, config := range []string{
		`{"tcp_fast_open":true,"bind_interface":"lo"}`,
		`{"tcp_fast_open":true,"inet4_bind_address":"127.0.0.1"}`,
	} {
		t.Run(config, func(t *testing.T) {
			destination := networkTFOListener(t, "tcp4")
			ctx := tfoContext(t, adapter.NetworkOptions{}, nil)
			manager := service.FromContext[adapter.NetworkManager](ctx).(*tfoNetworkManager)
			manager.interfaces[0].Addresses = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8")}
			manager.loopback = &control.Interface{Name: "cellular-default", Index: 12345}
			manager.interfaces = append(manager.interfaces, adapter.NetworkInterface{Interface: *manager.loopback, Type: C.InterfaceTypeCellular})
			publishTFOPolicy(manager)
			dialer, err := NewDefault(ctx, tfoOptions(t, config))
			if err != nil {
				t.Fatal(err)
			}
			dialer.androidTFO = true
			conn, err := dialer.DialContext(ctx, "tcp", destination)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := networkTFOExchange(conn, true); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPlatformTFONetworkMissingRecordAtFirstWrite(t *testing.T) {
	destination := networkTFOListener(t, "tcp4")
	ctx := tfoContext(t, adapter.NetworkOptions{}, nil)
	manager := service.FromContext[adapter.NetworkManager](ctx).(*tfoNetworkManager)
	publishTFOPolicy(manager)
	dialer, err := NewDefault(ctx, tfoOptions(t, `{"tcp_fast_open":true}`))
	if err != nil {
		t.Fatal(err)
	}
	dialer.androidTFO = true
	conn, err := dialer.DialContext(ctx, "tcp", destination)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	manager.interfaces = nil
	publishTFOPolicy(manager)
	if err := networkTFOExchange(conn, false); err != nil {
		t.Fatal(err)
	}
}

func TestPlatformTFONetworkCustomMarkPreserved(t *testing.T) {
	destination := networkTFOListener(t, "tcp4")
	ctx := tfoContext(t, adapter.NetworkOptions{}, nil)
	manager := service.FromContext[adapter.NetworkManager](ctx).(*tfoNetworkManager)
	publishTFOPolicy(manager)
	dialer, err := NewDefault(ctx, tfoOptions(t, `{"tcp_fast_open":true,"routing_mark":42}`))
	if err != nil {
		t.Fatal(err)
	}
	dialer.androidTFO = true
	conn, err := dialer.DialContext(ctx, "tcp", destination)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := networkTFOExchange(conn, false); err != nil {
		t.Fatal(err)
	}
	raw, err := conn.(*slowOpenConn).Upstream().(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var mark int
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		mark, socketErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK)
	}); err != nil {
		t.Fatal(err)
	}
	if socketErr != nil || mark != 42 {
		t.Fatalf("routing mark=%d err=%v", mark, socketErr)
	}
}

func TestPlatformTFONetworkPolicyNoAllocations(t *testing.T) {
	ctx := tfoContext(t, adapter.NetworkOptions{}, nil)
	manager := service.FromContext[adapter.NetworkManager](ctx).(*tfoNetworkManager)
	dialer, err := NewDefault(ctx, tfoOptions(t, `{"tcp_fast_open":true}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []C.InterfaceType{C.InterfaceTypeWIFI, C.InterfaceTypeCellular} {
		manager.interfaces[0].Type = kind
		publishTFOPolicy(manager)
		for _, ipv6 := range []bool{false, true} {
			selectDialer := dialer.selectTFO4
			if ipv6 {
				selectDialer = dialer.selectTFO6
			}
			selected := selectDialer()
			reads := manager.interfaceReads.Load()
			allocations := testing.AllocsPerRun(1000, func() { selected = selectDialer() })
			if allocations != 0 || manager.interfaceReads.Load() != reads {
				t.Fatalf("per-connection policy allocated or enumerated interfaces: allocations=%v", allocations)
			}
			if selected.DisableTFO != (kind == C.InterfaceTypeCellular) {
				t.Fatal("unexpected cached policy")
			}
		}
	}
}

func TestPlatformTFONetworkConcurrentPolicyPublication(t *testing.T) {
	ctx := tfoContext(t, adapter.NetworkOptions{}, nil)
	manager := service.FromContext[adapter.NetworkManager](ctx).(*tfoNetworkManager)
	wifi := adapter.NewNetworkTFOState(manager.loopback.Index, manager.interfaces)
	manager.interfaces[0].Type = C.InterfaceTypeCellular
	cell := adapter.NewNetworkTFOState(manager.loopback.Index, manager.interfaces)
	manager.tfoState.Store(cell)
	dialer, err := NewDefault(ctx, tfoOptions(t, `{"tcp_fast_open":true}`))
	if err != nil {
		t.Fatal(err)
	}
	ordinary := dialer.selectTFO4()
	var group sync.WaitGroup
	group.Go(func() {
		for range 1000 {
			manager.tfoState.Store(wifi)
			manager.tfoState.Store(cell)
		}
	})
	for range 16 {
		group.Go(func() {
			for range 1000 {
				selected := dialer.selectTFO4()
				if selected != &dialer.dialer4 && selected != ordinary {
					t.Error("selection created a new dialer")
				}
				if selected.DisableTFO != (selected == ordinary) {
					t.Error("shared dialer was mutated")
				}
			}
		})
	}
	group.Wait()
}

// This measures the complete added per-connection policy selection. Dialers and
// immutable policy snapshots are prepared before timing; no Android call exists.
func BenchmarkPlatformTFONetworkPolicy(b *testing.B) {
	for _, kind := range []C.InterfaceType{C.InterfaceTypeWIFI, C.InterfaceTypeCellular} {
		b.Run(kind.String(), func(b *testing.B) {
			iif := control.Interface{Name: "physical", Index: 1}
			manager := &tfoNetworkManager{}
			manager.tfoState.Store(adapter.NewNetworkTFOState(1, []adapter.NetworkInterface{{Interface: iif, Type: kind}}))
			dialer := &DefaultDialer{networkManager: manager}
			selectDialer := newNetworkTFOSelector(&dialer.dialer4, manager, option.DialerOptions{TCPFastOpen: true})
			b.ReportAllocs()
			for b.Loop() {
				selected := selectDialer()
				if selected.DisableTFO != (kind == C.InterfaceTypeCellular) {
					b.Fatal("unexpected policy")
				}
			}
		})
	}
}
