package dialer

import (
	"context"
	"net"
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
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

// Prepare both choices once, while constructing the outbound. New connections
// read an event-updated snapshot; they do not copy dialers or call Android.
func newNetworkTFOSelector(base *tfo.Dialer, manager adapter.NetworkManager, options option.DialerOptions) func() *tfo.Dialer {
	ordinary := *base
	ordinary.DisableTFO = true
	provider, ok := manager.(adapter.NetworkTFOProvider)
	if !ok || options.NetNs != "" || options.RoutingMark != 0 || manager.DefaultOptions().RoutingMark != 0 {
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
	return func() *tfo.Dialer {
		if provider.NetworkTFOState().Allowed(bindInterface, localIP) {
			return base
		}
		return &ordinary
	}
}
