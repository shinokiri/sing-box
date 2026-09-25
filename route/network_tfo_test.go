package route

import (
	"net"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"
)

type networkTFOTestMonitor struct {
	tun.DefaultInterfaceMonitor
	current *control.Interface
}

func (m *networkTFOTestMonitor) DefaultInterface() *control.Interface { return m.current }

type networkTFOTestPlatform struct {
	adapter.PlatformInterface
	interfaces []adapter.NetworkInterface
}

func (p *networkTFOTestPlatform) UsePlatformNetworkInterfaces() bool { return true }
func (p *networkTFOTestPlatform) NetworkInterfaces() ([]adapter.NetworkInterface, error) {
	return p.interfaces, nil
}

func TestNetworkTFOEventPublication(t *testing.T) {
	wifi := control.Interface{Name: "wifi", Index: 1, Flags: net.FlagUp}
	cell := control.Interface{Name: "cellular", Index: 2, Flags: net.FlagUp}
	monitor := &networkTFOTestMonitor{current: &wifi}
	platform := &networkTFOTestPlatform{interfaces: []adapter.NetworkInterface{
		{Interface: wifi, Type: C.InterfaceTypeWIFI},
		{Interface: cell, Type: C.InterfaceTypeCellular},
	}}
	manager := &NetworkManager{
		logger: logger.NOP(),
		interfaceFinder: control.NewDefaultInterfaceFinder(),
		interfaceMonitor: monitor,
		platformInterface: platform,
		networkTFOPolicy: true,
	}
	refresh := func() {
		t.Helper()
		if err := manager.UpdateInterfaces(); err != nil {
			t.Fatal(err)
		}
		manager.environmentUpdateAccess.Lock()
		manager.environmentUpdateTimer.Stop()
		manager.environmentUpdateAccess.Unlock()
	}
	allowed := func() bool { return manager.NetworkTFOState().Allowed("", netip.Addr{}) }
	if allowed() {
		t.Fatal("uninitialized policy allowed TFO")
	}
	refresh()
	if !allowed() {
		t.Fatal("coexisting cellular network suppressed Wi-Fi")
	}
	oldSnapshot := manager.NetworkTFOState()
	monitor.current = &cell
	manager.notifyInterfaceUpdate(&cell, 0)
	if allowed() || !oldSnapshot.Allowed("", netip.Addr{}) {
		t.Fatal("default change did not publish a new immutable cellular policy")
	}
	monitor.current = &wifi
	manager.notifyInterfaceUpdate(&wifi, 0)
	if !allowed() {
		t.Fatal("Wi-Fi restoration did not update the policy")
	}
	// Capability changes can refresh interfaces without changing name/index.
	platform.interfaces[0].Type = C.InterfaceTypeCellular
	refresh()
	if allowed() {
		t.Fatal("same-interface capability change was ignored")
	}
	monitor.current = nil
	manager.notifyInterfaceUpdate(nil, 0)
	if allowed() {
		t.Fatal("lost default network kept TFO enabled")
	}
	monitor.current = &wifi
	platform.interfaces = nil
	refresh()
	if allowed() {
		t.Fatal("missing interface record used the Wi-Fi enum's zero value")
	}
}
