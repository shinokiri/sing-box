//go:build linux

package dialer

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"

	"golang.org/x/sys/unix"
)

func setTestNetworkBinder(d *DefaultDialer, options option.DialerOptions, bind networkBinder) {
	d.bindNetwork = bind
	d.selectTFO4 = newNetworkTFOSelector(&d.dialer4, d.networkManager, options, bind)
	d.selectTFO6 = newNetworkTFOSelector(&d.dialer6, d.networkManager, options, bind)
}

func socketMark(t *testing.T, conn net.Conn) uint64 {
	t.Helper()
	if wrapped, ok := conn.(interface{ Upstream() any }); ok {
		conn = wrapped.Upstream().(net.Conn)
	}
	raw, err := conn.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var mark int
	if err := control.Raw(raw, func(fd uintptr) error {
		mark, err = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return uint64(mark)
}

func testMarkNetwork(fd uintptr, handle uint64) error {
	// Linux's test fixture maps each fake Android Network handle to a policy
	// routing mark. Production uses android_setsocknetwork, never SO_MARK.
	if _, err := unix.Getpeername(int(fd)); !errors.Is(err, unix.ENOTCONN) {
		return fmt.Errorf("network binding ran after connect: %v", err)
	}
	return unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(handle))
}

func TestPlatformTFONetworkBindingSnapshot(t *testing.T) {
	for _, family := range []string{"tcp4", "tcp6"} {
		t.Run(family, func(t *testing.T) {
			destination := networkTFOListener(t, family)
			var manager *tfoNetworkManager
			var protects atomic.Int32
			ctx := tfoContext(t, adapter.NetworkOptions{}, func(string, string, syscall.RawConn) error {
				protects.Add(1)
				// Simulate a network event after selection but before socket bind.
				manager.interfaces[0].Type = C.InterfaceTypeCellular
				manager.interfaces[0].NetworkHandle = 102
				manager.tfoState.Store(adapter.NewNetworkTFOState(manager.loopback.Index, manager.interfaces))
				return nil
			})
			manager = service.FromContext[adapter.NetworkManager](ctx).(*tfoNetworkManager)
			manager.interfaces[0].NetworkHandle = 101
			manager.tfoState.Store(adapter.NewNetworkTFOState(manager.loopback.Index, manager.interfaces))
			options := tfoOptions(t, `{"tcp_fast_open":true}`)
			d, err := newNetworkTFODialer(ctx, options)
			if err != nil {
				t.Fatal(err)
			}
			setTestNetworkBinder(d, options, testMarkNetwork)
			for i, handle := range []uint64{101, 102} {
				conn, err := d.DialContext(ctx, family, destination)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				if err := networkTFOExchange(conn, i == 0); err != nil {
					t.Fatal(err)
				}
				if got := socketMark(t, conn); got != handle {
					t.Fatalf("bound handle=%d, want %d", got, handle)
				}
			}
			if protects.Load() != 2 {
				t.Fatalf("protect calls=%d", protects.Load())
			}
		})
	}
}

func TestPlatformTFONetworkRequiresBindingIdentity(t *testing.T) {
	for _, family := range []string{"tcp4", "tcp6"} {
		t.Run(family, func(t *testing.T) {
			destination := networkTFOListener(t, family)
			ctx := tfoContext(t, adapter.NetworkOptions{}, nil)
			manager := service.FromContext[adapter.NetworkManager](ctx).(*tfoNetworkManager)
			// Wi-Fi classification without a Network handle cannot justify TFO.
			manager.tfoState.Store(adapter.NewNetworkTFOState(manager.loopback.Index, manager.interfaces))
			d, err := newNetworkTFODialer(ctx, tfoOptions(t, `{"tcp_fast_open":true}`))
			if err != nil {
				t.Fatal(err)
			}
			conn, err := d.DialContext(ctx, family, destination)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := networkTFOExchange(conn, false); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPlatformNetworkBindingFailureIsNotRetriedUnbound(t *testing.T) {
	for _, mode := range []string{"tcp", "tfo", "udp", "packet", "icmp"} {
		t.Run(mode, func(t *testing.T) {
			var protects, bindings atomic.Int32
			ctx := tfoContext(t, adapter.NetworkOptions{}, func(string, string, syscall.RawConn) error { protects.Add(1); return nil })
			manager := service.FromContext[adapter.NetworkManager](ctx).(*tfoNetworkManager)
			publishTFOPolicy(manager)
			options := tfoOptions(t, fmt.Sprintf(`{"tcp_fast_open":%v}`, mode == "tfo"))
			d, err := newNetworkTFODialer(ctx, options)
			if err != nil {
				t.Fatal(err)
			}
			setTestNetworkBinder(d, options, func(uintptr, uint64) error { bindings.Add(1); return unix.EPERM })
			destination := M.ParseSocksaddr("127.0.0.1:1")
			switch mode {
			case "packet":
				var conn net.PacketConn
				conn, err = d.ListenPacket(ctx, destination)
				if conn != nil {
					conn.Close()
				}
			case "icmp":
				listener := net.ListenConfig{Control: d.ICMPControl()}
				var conn net.PacketConn
				conn, err = listener.ListenPacket(ctx, "udp4", "127.0.0.1:0")
				if conn != nil {
					conn.Close()
				}
			default:
				network := "tcp"
				if mode == "udp" {
					network = "udp"
				}
				var conn net.Conn
				conn, err = d.DialContext(ctx, network, destination)
				if conn != nil {
					defer conn.Close()
					_, err = conn.Write([]byte("ping"))
				}
			}
			if !errors.Is(err, errNetworkBinding) || !errors.Is(err, unix.EPERM) || bindings.Load() != 1 || protects.Load() != 1 || d.networkStrategy == nil {
				t.Fatalf("binding failure escaped: err=%v binds=%d protects=%d strategy=%v", err, bindings.Load(), protects.Load(), d.networkStrategy)
			}
		})
	}
}

// Run by .github/test_android_network_routes.sh in an isolated Linux network
// namespace. The unbound host route goes over cellular; a selected Network
// must override it for both ordinary TCP and TFO, including a delayed write.
func TestPlatformNetworkDestinationRoute(t *testing.T) {
	if os.Getenv("SING_BOX_TEST_ANDROID_POLICY_ROUTES") != "1" {
		t.Skip("requires isolated policy-route fixture")
	}
	wifi, err := net.InterfaceByName("wifi0")
	if err != nil {
		t.Fatal(err)
	}
	cell, err := net.InterfaceByName("cell0")
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range []string{"tcp4", "tcp6"} {
		endpoint, wifiSource, cellSource := "203.0.113.1:18080", "192.0.2.2", "198.51.100.2"
		if family == "tcp6" {
			endpoint, wifiSource, cellSource = "[2001:db8:ffff::1]:18080", "2001:db8:1::2", "2001:db8:2::2"
		}
		t.Run(family, func(t *testing.T) {
			baseline, err := net.Dial(family, endpoint)
			if err != nil {
				t.Fatal(err)
			}
			if baseline.LocalAddr().(*net.TCPAddr).IP.String() != cellSource {
				t.Fatalf("fixture did not route unbound socket over cellular: %v", baseline.LocalAddr())
			}
			baseline.Close()
			for _, configured := range []bool{false, true} {
				for _, selectCell := range []bool{false, true} {
					t.Run(fmt.Sprintf("tfo=%v/cellular=%v", configured, selectCell), func(t *testing.T) {
						ctx := tfoContext(t, adapter.NetworkOptions{}, nil)
						manager := service.FromContext[adapter.NetworkManager](ctx).(*tfoNetworkManager)
						manager.interfaces = []adapter.NetworkInterface{
							{Interface: control.Interface{Name: wifi.Name, Index: wifi.Index}, Type: C.InterfaceTypeWIFI, NetworkHandle: 101},
							{Interface: control.Interface{Name: cell.Name, Index: cell.Index}, Type: C.InterfaceTypeCellular, NetworkHandle: 102},
						}
						manager.loopback = &manager.interfaces[0].Interface
						manager.tfoState.Store(adapter.NewNetworkTFOState(manager.loopback.Index, manager.interfaces))
						options := tfoOptions(t, fmt.Sprintf(`{"tcp_fast_open":%v}`, configured))
						d, err := newNetworkTFODialer(ctx, options)
						if err != nil {
							t.Fatal(err)
						}
						setTestNetworkBinder(d, options, testMarkNetwork)
						setCell := func() {
							manager.loopback = &manager.interfaces[1].Interface
							manager.tfoState.Store(adapter.NewNetworkTFOState(manager.loopback.Index, manager.interfaces))
						}
						if selectCell && !configured {
							setCell()
						}
						conn, err := d.DialContext(ctx, family, M.ParseSocksaddr(endpoint))
						if err != nil {
							t.Fatal(err)
						}
						defer conn.Close()
						if selectCell && configured {
							setCell()
						}
						if err := networkTFOExchange(conn, configured && !selectCell); err != nil {
							t.Fatal(err)
						}
						want := wifiSource
						if selectCell {
							want = cellSource
						}
						got := M.SocksaddrFromNet(conn.LocalAddr()).Addr.Unmap()
						if got != netip.MustParseAddr(want) {
							t.Fatalf("actual source=%s, want %s", got, want)
						}
					})
				}
			}
		})
	}
}
