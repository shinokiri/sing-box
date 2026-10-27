package dialer

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/database64128/tfo-go/v2"
)

func (d *DefaultDialer) dialSlowContext(base *tfo.Dialer, ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if !d.androidTFO || base.DisableTFO || N.NetworkName(network) != N.NetworkTCP {
		return dialSlowContext(base, ctx, network, destination, d.netns)
	}
	selectDialer := d.selectTFO4
	if base == &d.dialer6 {
		selectDialer = d.selectTFO6
	}
	return newSlowOpenConn(base, ctx, network, destination, d.netns, selectDialer), nil
}

// Keep one prepared choice per address family. The steady-state first-write
// selection does not allocate or enumerate interfaces. A changed selection
// creates an immutable dialer whose TFO policy and binding use the same handle.
func newNetworkTFOSelector(base *tfo.Dialer, manager adapter.NetworkManager, options option.DialerOptions, bind networkBinder) func() *tfo.Dialer {
	ordinary := *base
	ordinary.DisableTFO = true
	provider, ok := manager.(adapter.NetworkTFOProvider)
	if !ok || bind == nil || options.NetNs != "" || options.RoutingMark != 0 || manager.DefaultOptions().RoutingMark != 0 {
		return func() *tfo.Dialer { return &ordinary }
	}
	bindInterface := options.BindInterface
	if bindInterface == "" && options.Inet4BindAddress == nil && options.Inet6BindAddress == nil {
		bindInterface = manager.DefaultOptions().BindInterface
	}
	var localIP netip.Addr
	if addr, ok := base.LocalAddr.(*net.TCPAddr); ok && !addr.IP.IsUnspecified() {
		localIP, _ = netip.AddrFromSlice(addr.IP)
		localIP = localIP.Unmap()
	}
	type choice struct {
		selection adapter.NetworkTFOSelection
		dialer    tfo.Dialer
	}
	var cached atomic.Pointer[choice]
	return func() *tfo.Dialer {
		selection := provider.NetworkTFOState().Select(bindInterface, localIP)
		if selection.NetworkHandle == 0 {
			// A default interface classification alone cannot establish which
			// network a destination-specific Android route will actually use.
			return &ordinary
		}
		if previous := cached.Load(); previous != nil && previous.selection == selection {
			return &previous.dialer
		}
		next := &choice{selection: selection, dialer: *base}
		next.dialer.DisableTFO = base.DisableTFO || !selection.Allowed
		next.dialer.Control = control.Append(base.Control, networkControl(bind, selection.NetworkHandle))
		cached.Store(next)
		return &next.dialer
	}
}
