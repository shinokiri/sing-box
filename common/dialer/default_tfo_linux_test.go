//go:build linux

package dialer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"

	"golang.org/x/sys/unix"
)

type tfoPlatform struct {
	adapter.PlatformInterface
}

func (tfoPlatform) UsePlatformNetworkInterfaces() bool { return true }

type tfoInterfaceMonitor struct {
	tun.DefaultInterfaceMonitor
	loopback *control.Interface
}

func (m tfoInterfaceMonitor) DefaultInterface() *control.Interface { return m.loopback }
func (m tfoInterfaceMonitor) MyInterfaces() []string               { return nil }

type tfoNetworkManager struct {
	adapter.NetworkManager
	defaults   adapter.NetworkOptions
	protect    control.Func
	loopback   *control.Interface
	interfaces []adapter.NetworkInterface
	tfoState atomic.Pointer[adapter.NetworkTFOState]
	interfaceReads atomic.Int64
}

func (m *tfoNetworkManager) InterfaceFinder() control.InterfaceFinder {
	return control.NewDefaultInterfaceFinder()
}
func (m *tfoNetworkManager) AutoDetectInterface() bool                { return true }
func (m *tfoNetworkManager) DefaultOptions() adapter.NetworkOptions   { return m.defaults }
func (m *tfoNetworkManager) ProtectFunc() control.Func                { return m.protect }
func (m *tfoNetworkManager) AutoDetectInterfaceFunc() control.Func    { return m.protect }
func (m *tfoNetworkManager) AutoRedirectOutputMarkFunc() control.Func { return nil }
func (m *tfoNetworkManager) AutoRedirectOutputMark() uint32           { return 0 }
func (m *tfoNetworkManager) InterfaceMonitor() tun.DefaultInterfaceMonitor {
	return tfoInterfaceMonitor{loopback: m.loopback}
}
func (m *tfoNetworkManager) NetworkInterfaces() []adapter.NetworkInterface {
	m.interfaceReads.Add(1)
	return m.interfaces
}

func (m *tfoNetworkManager) NetworkTFOState() *adapter.NetworkTFOState {
	return m.tfoState.Load()
}

func tfoContext(t *testing.T, defaults adapter.NetworkOptions, protect control.Func) context.Context {
	t.Helper()
	loopback, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	ctx := service.ContextWithDefaultRegistry(context.Background())
	service.MustRegister[adapter.NetworkManager](ctx, &tfoNetworkManager{
		defaults:   defaults,
		protect:    protect,
		loopback:   &control.Interface{Name: loopback.Name, Index: loopback.Index},
		interfaces: []adapter.NetworkInterface{{Interface: control.Interface{Name: loopback.Name, Index: loopback.Index}}},
	})
	service.MustRegister[adapter.PlatformInterface](ctx, tfoPlatform{})
	return ctx
}

func tfoOptions(t *testing.T, content string) option.DialerOptions {
	t.Helper()
	var options option.DialerOptions
	if err := json.Unmarshal([]byte(content), &options); err != nil {
		t.Fatal(err)
	}
	return options
}

// Exercise real kernel sockets through the Android platform-interface branch.
// Checking TCP_FASTOPEN_CONNECT distinguishes an ordinary successful TCP
// connection from a dial which actually requested TFO, even without a cookie.
func TestPlatformTCPFastOpen(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		for _, enabled := range []bool{false, true} {
			for _, parallelEntry := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/enabled=%v/interface_entry=%v", network, enabled, parallelEntry), func(t *testing.T) {
					address := "127.0.0.1:0"
					if network == "tcp6" {
						address = "[::1]:0"
					}
					listener, err := net.Listen(network, address)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { listener.Close() })
					listener.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second))
					serverResult := make(chan error, 1)
					go func() {
						peer, err := listener.Accept()
						if err != nil {
							serverResult <- err
							return
						}
						defer peer.Close()
						peer.SetDeadline(time.Now().Add(5 * time.Second))
						payload := make([]byte, 4)
						_, err = io.ReadFull(peer, payload)
						if err == nil && string(payload) != "ping" {
							err = fmt.Errorf("unexpected payload: %q", payload)
						}
						if err == nil {
							_, err = peer.Write(payload)
						}
						serverResult <- err
					}()
					var protected atomic.Int32
					ctx := tfoContext(t, adapter.NetworkOptions{}, func(string, string, syscall.RawConn) error {
						protected.Add(1)
						return nil
					})
					ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
					defer cancel()
					dialer, err := NewDefault(ctx, tfoOptions(t, fmt.Sprintf(`{"tcp_fast_open":%v}`, enabled)))
					if err != nil {
						t.Fatal(err)
					}
					destination := M.ParseSocksaddr(listener.Addr().String())
					var conn net.Conn
					if parallelEntry {
						strategy := C.NetworkStrategyDefault
						conn, err = dialer.DialParallelInterface(ctx, "tcp", destination, &strategy, nil, nil, 0)
					} else {
						conn, err = dialer.DialContext(ctx, "tcp", destination)
					}
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { conn.Close() })
					if _, err = conn.Write([]byte("ping")); err != nil {
						t.Fatal(err)
					}
					if err = conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
						t.Fatal(err)
					}
					response := make([]byte, 4)
					if _, err = io.ReadFull(conn, response); err != nil {
						t.Fatal(err)
					}
					if string(response) != "ping" {
						t.Fatalf("response: %q", response)
					}
					if err = <-serverResult; err != nil {
						t.Fatal(err)
					}
					if protected.Load() != 1 {
						t.Fatalf("protect calls: %d", protected.Load())
					}
					var underlying any = conn
					if wrapped, ok := underlying.(interface{ Upstream() any }); ok {
						underlying = wrapped.Upstream()
					}
					tcp, ok := underlying.(*net.TCPConn)
					if !ok {
						t.Fatalf("unexpected socket wrapper: %T", underlying)
					}
					raw, err := tcp.SyscallConn()
					if err != nil {
						t.Fatal(err)
					}
					var socketValue int
					var socketErr error
					if err = raw.Control(func(fd uintptr) {
						socketValue, socketErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_FASTOPEN_CONNECT)
					}); err != nil {
						t.Fatal(err)
					}
					if socketErr != nil {
						t.Fatal(socketErr)
					}
					if (socketValue != 0) != enabled {
						t.Fatalf("TCP_FASTOPEN_CONNECT=%d, want enabled=%v", socketValue, enabled)
					}
				})
			}
		}
	}
}

func TestPlatformTFOProtectionFailure(t *testing.T) {
	failure := errors.New("platform protect failed")
	ctx := tfoContext(t, adapter.NetworkOptions{}, func(string, string, syscall.RawConn) error { return failure })
	dialer, err := NewDefault(ctx, tfoOptions(t, `{"tcp_fast_open":true}`))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dialer.DialContext(ctx, "tcp", M.ParseSocksaddr("127.0.0.1:1"))
	if err == nil {
		defer conn.Close()
		_, err = conn.Write([]byte("ping"))
	}
	if !errors.Is(err, failure) {
		t.Fatalf("protect failure not propagated: %v", err)
	}
}

func TestPlatformTFORejectsNetworkOverrides(t *testing.T) {
	hybrid := C.NetworkStrategyHybrid
	fallback := C.NetworkStrategyFallback
	for _, test := range []struct {
		name     string
		defaults adapter.NetworkOptions
		options  string
	}{
		{"inherited_hybrid", adapter.NetworkOptions{NetworkStrategy: &hybrid}, `{"tcp_fast_open":true}`},
		{"inherited_fallback", adapter.NetworkOptions{NetworkStrategy: &fallback}, `{"tcp_fast_open":true}`},
		{"inherited_type", adapter.NetworkOptions{NetworkType: []C.InterfaceType{C.InterfaceTypeWIFI}}, `{"tcp_fast_open":true}`},
		{"inherited_fallback_type", adapter.NetworkOptions{FallbackNetworkType: []C.InterfaceType{C.InterfaceTypeWIFI}}, `{"tcp_fast_open":true}`},
		{"outbound_strategy", adapter.NetworkOptions{}, `{"tcp_fast_open":true,"network_strategy":"hybrid"}`},
		{"outbound_types", adapter.NetworkOptions{}, `{"tcp_fast_open":true,"network_type":["wifi"],"fallback_network_type":["cellular"]}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := tfoContext(t, test.defaults, nil)
			_, err := NewDefault(ctx, tfoOptions(t, test.options))
			if err == nil || !strings.Contains(err.Error(), "tcp_fast_open") {
				t.Fatalf("unsupported TFO network selection was accepted: %v", err)
			}
		})
	}
}

func TestPlatformTFODynamicNetworkOverride(t *testing.T) {
	for _, resolved := range []bool{false, true} {
		t.Run(fmt.Sprintf("resolved=%v", resolved), func(t *testing.T) {
			ctx := tfoContext(t, adapter.NetworkOptions{}, nil)
			base, err := NewDefault(ctx, tfoOptions(t, `{"tcp_fast_open":true}`))
			if err != nil {
				t.Fatal(err)
			}
			var dialer ParallelInterfaceDialer = base
			if resolved {
				dialer = NewResolveDialer(ctx, base, false, "", adapter.DNSQueryOptions{}, 0).(ParallelInterfaceDialer)
			}
			strategy := C.NetworkStrategyHybrid
			conn, err := dialer.DialParallelInterface(ctx, "tcp", M.ParseSocksaddr("127.0.0.1:1"), &strategy, nil, nil, 0)
			if conn != nil {
				conn.Close()
			}
			if err == nil || !strings.Contains(err.Error(), "tcp_fast_open") {
				t.Fatalf("dynamic override did not report TFO incompatibility: %v", err)
			}
		})
	}
}

func TestPlatformTFONetworkAvailability(t *testing.T) {
	for _, count := range []int{0, 2} {
		t.Run(fmt.Sprintf("interfaces=%d", count), func(t *testing.T) {
			var protected atomic.Int32
			ctx := tfoContext(t, adapter.NetworkOptions{}, func(string, string, syscall.RawConn) error {
				protected.Add(1)
				return nil
			})
			manager := service.FromContext[adapter.NetworkManager](ctx).(*tfoNetworkManager)
			manager.loopback = nil
			manager.interfaces = nil
			for index := range count {
				manager.interfaces = append(manager.interfaces, adapter.NetworkInterface{
					Interface: control.Interface{Name: fmt.Sprintf("test%d", index), Index: index + 100},
				})
			}
			dialer, err := NewDefault(ctx, tfoOptions(t, `{"tcp_fast_open":true}`))
			if err != nil {
				t.Fatal(err)
			}
			conn, err := dialer.DialContext(ctx, "tcp", M.ParseSocksaddr("127.0.0.1:1"))
			if conn != nil {
				conn.Close()
			}
			want := "no available network interface"
			if count > 1 {
				want = "requires a default network interface"
			}
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("network selection: %v, want %q", err, want)
			}
			if protected.Load() != 0 {
				t.Fatal("opened a socket without selecting an interface")
			}
		})
	}
}

func TestPlatformTFOUDP(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			address := "127.0.0.1:0"
			if network == "udp6" {
				address = "[::1]:0"
			}
			server, err := net.ListenPacket(network, address)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			server.SetDeadline(time.Now().Add(5 * time.Second))
			var protected atomic.Int32
			ctx := tfoContext(t, adapter.NetworkOptions{}, func(string, string, syscall.RawConn) error {
				protected.Add(1)
				return nil
			})
			dialer, err := NewDefault(ctx, tfoOptions(t, `{"tcp_fast_open":true}`))
			if err != nil {
				t.Fatal(err)
			}
			conn, err := dialer.DialContext(ctx, "udp", M.ParseSocksaddr(server.LocalAddr().String()))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err = conn.Write([]byte("udp")); err != nil {
				t.Fatal(err)
			}
			payload := make([]byte, 16)
			n, peer, err := server.ReadFrom(payload)
			if err != nil || string(payload[:n]) != "udp" {
				t.Fatalf("UDP request: %q, %v", payload[:n], err)
			}
			if _, err = server.WriteTo(payload[:n], peer); err != nil {
				t.Fatal(err)
			}
			n, err = conn.Read(payload)
			if err != nil || string(payload[:n]) != "udp" {
				t.Fatalf("UDP response: %q, %v", payload[:n], err)
			}
			if protected.Load() != 1 {
				t.Fatalf("protect calls: %d", protected.Load())
			}
		})
	}
}

func TestPlatformTFOSoleInterface(t *testing.T) {
	server, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	server.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second))
	var protected atomic.Int32
	ctx := tfoContext(t, adapter.NetworkOptions{}, func(string, string, syscall.RawConn) error {
		protected.Add(1)
		return nil
	})
	service.FromContext[adapter.NetworkManager](ctx).(*tfoNetworkManager).loopback = nil
	dialer, err := NewDefault(ctx, tfoOptions(t, `{"tcp_fast_open":true}`))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dialer.DialContext(ctx, "tcp", M.ParseSocksaddr(server.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err = conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	peer, err := server.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	peer.SetDeadline(time.Now().Add(5 * time.Second))
	payload := make([]byte, 4)
	if _, err = io.ReadFull(peer, payload); err != nil || string(payload) != "ping" {
		t.Fatalf("bound-interface payload: %q, %v", payload, err)
	}
	raw, err := conn.(*slowOpenConn).conn.Load().SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var device string
	var fastOpen int
	var socketErr error
	if err = raw.Control(func(fd uintptr) {
		device, socketErr = unix.GetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
		if socketErr == nil {
			fastOpen, socketErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_FASTOPEN_CONNECT)
		}
	}); err != nil {
		t.Fatal(err)
	}
	// control.BindToInterface deliberately skips virtual destinations such
	// as loopback; selecting the sole interface must still retain TFO/protect.
	if socketErr != nil || device != "" || fastOpen != 1 || protected.Load() != 1 {
		t.Fatalf("device=%q, TFO=%d, protect calls=%d, error=%v", device, fastOpen, protected.Load(), socketErr)
	}
}

func TestPlatformTFONetworkNamespace(t *testing.T) {
	var protected atomic.Int32
	ctx := tfoContext(t, adapter.NetworkOptions{}, func(string, string, syscall.RawConn) error {
		protected.Add(1)
		return nil
	})
	options := tfoOptions(t, `{"tcp_fast_open":true}`)
	options.NetNs = filepath.Join(t.TempDir(), "missing-netns")
	dialer, err := NewDefault(ctx, options)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dialer.DialContext(ctx, "tcp", M.ParseSocksaddr("127.0.0.1:1"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	n, err := conn.Write([]byte("ping"))
	if !errors.Is(err, os.ErrNotExist) || n != 0 || protected.Load() != 0 {
		t.Fatalf("namespace was ignored: n=%d, error=%v, protect calls=%d", n, err, protected.Load())
	}
}

func TestPlatformTFOCloseBeforeWrite(t *testing.T) {
	var protected atomic.Int32
	ctx := tfoContext(t, adapter.NetworkOptions{}, func(string, string, syscall.RawConn) error {
		protected.Add(1)
		return nil
	})
	dialer, err := NewDefault(ctx, tfoOptions(t, `{"tcp_fast_open":true}`))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dialer.DialContext(ctx, "tcp", M.ParseSocksaddr("127.0.0.1:1"))
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	n, err := conn.Write([]byte("ping"))
	if n != 0 || !errors.Is(err, os.ErrClosed) || protected.Load() != 0 {
		t.Fatalf("write after close: n=%d, error=%v, protect calls=%d", n, err, protected.Load())
	}
}

func TestPlatformTFOCloseDuringDial(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	ctx := tfoContext(t, adapter.NetworkOptions{}, func(string, string, syscall.RawConn) error {
		close(entered)
		<-release
		return nil
	})
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	dialer, err := NewDefault(ctx, tfoOptions(t, `{"tcp_fast_open":true}`))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dialer.DialContext(ctx, "tcp", M.ParseSocksaddr("127.0.0.1:1"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	type result struct {
		n   int
		err error
	}
	completed := make(chan result, 1)
	go func() {
		n, err := conn.Write([]byte("ping"))
		completed <- result{n, err}
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("first write did not open a socket")
	}
	conn.Close()
	close(release)
	select {
	case r := <-completed:
		if r.n != 0 || r.err == nil {
			t.Fatalf("pending write survived close: n=%d, error=%v", r.n, r.err)
		}
	case <-ctx.Done():
		t.Fatal("close did not cancel the pending dial")
	}
}

func TestPlatformTFOInterfaceBindingFailure(t *testing.T) {
	var protected atomic.Int32
	ctx := tfoContext(t, adapter.NetworkOptions{}, func(string, string, syscall.RawConn) error {
		protected.Add(1)
		return nil
	})
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	manager := service.FromContext[adapter.NetworkManager](ctx).(*tfoNetworkManager)
	manager.loopback = nil
	manager.interfaces = []adapter.NetworkInterface{{Interface: control.Interface{Name: "missing-tfo0", Index: 1000000}}}
	dialer, err := NewDefault(ctx, tfoOptions(t, `{"tcp_fast_open":true}`))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dialer.DialContext(ctx, "tcp", M.ParseSocksaddr("192.0.2.1:1"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	n, err := conn.Write([]byte("ping"))
	if n != 0 || !errors.Is(err, unix.ENODEV) || protected.Load() != 1 {
		t.Fatalf("interface binding was ignored: n=%d, error=%v, protect calls=%d", n, err, protected.Load())
	}
}

func TestPlatformTFOWriteAfterDialContextCanceled(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	listener.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second))
	ctx, cancel := context.WithCancel(tfoContext(t, adapter.NetworkOptions{}, nil))
	defer cancel()
	dialer, err := NewDefault(ctx, tfoOptions(t, `{"tcp_fast_open":true}`))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dialer.DialContext(ctx, "tcp", M.ParseSocksaddr(listener.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cancel()
	if n, err := conn.Write([]byte("ping")); err != nil || n != 4 {
		t.Fatalf("delayed first write was canceled with the completed dial: n=%d, err=%v", n, err)
	}
	peer, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	peer.SetReadDeadline(time.Now().Add(5 * time.Second))
	payload := make([]byte, 4)
	if _, err := io.ReadFull(peer, payload); err != nil {
		t.Fatal(err)
	}
	if string(payload) != "ping" {
		t.Fatalf("unexpected delayed payload: %q", payload)
	}
}
