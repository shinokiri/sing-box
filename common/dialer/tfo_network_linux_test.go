//go:build linux

package dialer

import (
	"context"
	"errors"
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

func TestPlatformTFONetworkPolicy(t *testing.T) {
	for _, family := range []string{"tcp4", "tcp6"} {
		for _, configured := range []bool{false, true} {
			for _, interfaceEntry := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/configured=%v/interface=%v", family, configured, interfaceEntry), func(t *testing.T) {
					destination := networkTFOListener(t, family)
					var protected, bound atomic.Int32
					ctx := tfoContext(t, adapter.NetworkOptions{}, func(string, string, syscall.RawConn) error {
						protected.Add(1)
						return nil
					})
					manager := service.FromContext[adapter.NetworkManager](ctx).(*tfoNetworkManager)
					dialer, err := NewDefault(ctx, tfoOptions(t, fmt.Sprintf(`{"tcp_fast_open":%v}`, configured)))
					if err != nil {
						t.Fatal(err)
					}
					// Execute the Android policy on a Linux kernel, where socket
					// options and actual data transfer can be checked in CI.
					dialer.androidTFO = true
					for _, tc := range []struct {
						name   string
						kind   C.InterfaceType
						binder bool
						want   bool
					}{
						{"wifi", C.InterfaceTypeWIFI, true, true},
						{"sim1", C.InterfaceTypeCellular, true, false},
						{"sim2", C.InterfaceTypeCellular, true, false},
						{"wifi-again", C.InterfaceTypeWIFI, true, true},
						{"ethernet", C.InterfaceTypeEthernet, true, true},
						{"other-physical", C.InterfaceTypeOther, true, true},
						{"missing-platform-binding", C.InterfaceTypeWIFI, false, false},
						{"unknown-type", C.InterfaceType(255), true, false},
					} {
						t.Run(tc.name, func(t *testing.T) {
							selected := adapter.NetworkInterface{Interface: *manager.loopback, Type: tc.kind}
							if tc.binder {
								selected.BindSocket = func(fd int) error {
									bound.Add(1)
									return unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, "lo")
								}
							}
							// Merely having another cellular network must not suppress
							// TFO on the selected Wi-Fi network.
							manager.interfaces = []adapter.NetworkInterface{selected, {
								Interface: control.Interface{Name: "unused-cellular", Index: 12345},
								Type:      C.InterfaceTypeCellular,
							}}
							beforeProtect, beforeBind := protected.Load(), bound.Load()
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
							if err := networkTFOExchange(conn, configured && tc.want); err != nil {
								t.Fatal(err)
							}
							wantBind := int32(0)
							if configured && tc.binder {
								wantBind = 1
							}
							if protected.Load()-beforeProtect != 1 || bound.Load()-beforeBind != wantBind {
								t.Fatalf("protect=%d bind=%d", protected.Load()-beforeProtect, bound.Load()-beforeBind)
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
				var boundType C.InterfaceType
				setNetwork := func(kind C.InterfaceType) {
					manager.interfaces = []adapter.NetworkInterface{{
						Interface: *manager.loopback, Type: kind,
						BindSocket: func(int) error { boundType = kind; return nil },
					}}
				}
				before, after := C.InterfaceTypeCellular, C.InterfaceTypeWIFI
				if toCellular {
					before, after = after, before
				}
				setNetwork(before)
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
				setNetwork(after)
				if err := networkTFOExchange(conn, !toCellular); err != nil {
					t.Fatal(err)
				}
				if boundType != after {
					t.Fatalf("bound %s, want %s", boundType, after)
				}
			})
		}
	}
}

func TestPlatformTFONetworkPinnedDuringSocketControl(t *testing.T) {
	destination := networkTFOListener(t, "tcp4")
	var manager *tfoNetworkManager
	var wifiBinds, cellBinds atomic.Int32
	ctx := tfoContext(t, adapter.NetworkOptions{}, func(string, string, syscall.RawConn) error {
		manager.interfaces = []adapter.NetworkInterface{{
			Interface: *manager.loopback, Type: C.InterfaceTypeCellular,
			BindSocket: func(int) error { cellBinds.Add(1); return nil },
		}}
		return nil
	})
	manager = service.FromContext[adapter.NetworkManager](ctx).(*tfoNetworkManager)
	manager.interfaces[0].BindSocket = func(int) error { wifiBinds.Add(1); return nil }
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
	if err := networkTFOExchange(conn, true); err != nil {
		t.Fatal(err)
	}
	if wifiBinds.Load() != 1 || cellBinds.Load() != 0 {
		t.Fatal("socket binding followed the new default after choosing TFO")
	}
}

func TestPlatformTFONetworkBindingFailure(t *testing.T) {
	failure := errors.New("physical network was lost")
	ctx := tfoContext(t, adapter.NetworkOptions{}, nil)
	manager := service.FromContext[adapter.NetworkManager](ctx).(*tfoNetworkManager)
	var calls atomic.Int32
	manager.interfaces[0].BindSocket = func(int) error { calls.Add(1); return failure }
	dialer, err := NewDefault(ctx, tfoOptions(t, `{"tcp_fast_open":true}`))
	if err != nil {
		t.Fatal(err)
	}
	dialer.androidTFO = true
	conn, err := dialer.DialContext(ctx, "tcp", M.ParseSocksaddr("127.0.0.1:1"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for range 2 {
		if n, err := conn.Write([]byte("ping")); n != 0 || !errors.Is(err, failure) {
			t.Fatalf("write after lost network: n=%d err=%v", n, err)
		}
	}
	if _, err := conn.Read(make([]byte, 4)); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("failed first write was retried")
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
			manager.interfaces[0].BindSocket = func(int) error { return nil }
			manager.loopback = &control.Interface{Name: "cellular-default", Index: 12345}
			manager.interfaces = append(manager.interfaces, adapter.NetworkInterface{Interface: *manager.loopback, Type: C.InterfaceTypeCellular})
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

func TestPlatformTFONetworkConcurrentConnections(t *testing.T) {
	for _, kind := range []C.InterfaceType{C.InterfaceTypeCellular, C.InterfaceTypeWIFI} {
		t.Run(kind.String(), func(t *testing.T) {
			destination := networkTFOListener(t, "tcp4")
			ctx := tfoContext(t, adapter.NetworkOptions{}, nil)
			manager := service.FromContext[adapter.NetworkManager](ctx).(*tfoNetworkManager)
			manager.interfaces[0].Type = kind
			manager.interfaces[0].BindSocket = func(int) error { return nil }
			dialer, err := NewDefault(ctx, tfoOptions(t, `{"tcp_fast_open":true}`))
			if err != nil {
				t.Fatal(err)
			}
			dialer.androidTFO = true
			var group sync.WaitGroup
			for range 16 {
				group.Go(func() {
					conn, err := dialer.DialContext(context.Background(), "tcp", destination)
					if err != nil {
						t.Error(err)
						return
					}
					defer conn.Close()
					if err := networkTFOExchange(conn, kind != C.InterfaceTypeCellular); err != nil {
						t.Error(err)
					}
				})
			}
			group.Wait()
		})
	}
}

func TestPlatformTFONetworkMissingRecordAtFirstWrite(t *testing.T) {
	destination := networkTFOListener(t, "tcp4")
	ctx := tfoContext(t, adapter.NetworkOptions{}, nil)
	manager := service.FromContext[adapter.NetworkManager](ctx).(*tfoNetworkManager)
	manager.interfaces[0].BindSocket = func(int) error { return nil }
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
	// The monitor still has an index but the refreshed platform list does not.
	manager.interfaces = nil
	if err := networkTFOExchange(conn, false); err != nil {
		t.Fatal(err)
	}
}

func TestPlatformTFONetworkCustomMarkPreserved(t *testing.T) {
	destination := networkTFOListener(t, "tcp4")
	ctx := tfoContext(t, adapter.NetworkOptions{}, nil)
	manager := service.FromContext[adapter.NetworkManager](ctx).(*tfoNetworkManager)
	manager.interfaces[0].BindSocket = func(int) error {
		return errors.New("platform network must not override an explicit mark")
	}
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
	tcp := conn.(*slowOpenConn).Upstream().(*net.TCPConn)
	raw, err := tcp.SyscallConn()
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

func TestPlatformTFONetworkCloseDuringBinding(t *testing.T) {
	ctx := tfoContext(t, adapter.NetworkOptions{}, nil)
	manager := service.FromContext[adapter.NetworkManager](ctx).(*tfoNetworkManager)
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	manager.interfaces[0].BindSocket = func(int) error {
		close(entered)
		<-release
		return nil
	}
	dialer, err := NewDefault(ctx, tfoOptions(t, `{"tcp_fast_open":true}`))
	if err != nil {
		t.Fatal(err)
	}
	dialer.androidTFO = true
	conn, err := dialer.DialContext(ctx, "tcp", M.ParseSocksaddr("127.0.0.1:1"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	result := make(chan error, 1)
	go func() {
		n, err := conn.Write([]byte("ping"))
		if n != 0 || err == nil {
			err = fmt.Errorf("write completed after close: n=%d err=%v", n, err)
		} else {
			err = nil
		}
		result <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("binding did not start")
	}
	conn.Close()
	unblock()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("close did not cancel the pending dial")
	}
}
