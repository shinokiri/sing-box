package dialer

import (
	"context"
	"net"
	"net/netip"
	"syscall"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/database64128/tfo-go/v2"
)

func tfoBoundInterface(manager adapter.NetworkManager, options option.DialerOptions) string {
	if options.BindInterface != "" {
		return options.BindInterface
	}
	if manager != nil && options.Inet4BindAddress == nil && options.Inet6BindAddress == nil {
		return manager.DefaultOptions().BindInterface
	}
	return ""
}

func (d *DefaultDialer) dialSlowContext(base *tfo.Dialer, ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if !d.androidTFO || base.DisableTFO || N.NetworkName(network) != N.NetworkTCP {
		return dialSlowContext(base, ctx, network, destination, d.netns)
	}
	return newSlowOpenConn(base, ctx, network, destination, d.netns, func() (*tfo.Dialer, error) {
		return d.prepareNetworkTFO(base)
	}), nil
}

func (d *DefaultDialer) prepareNetworkTFO(base *tfo.Dialer) (*tfo.Dialer, error) {
	// A dial owns its copy. Never change the shared IPv4/IPv6 TFO dialers.
	dialer := *base
	dialer.DisableTFO = true
	if d.networkManager == nil || d.tfoUnclassifiedRoute {
		// A custom mark or namespace may route outside the platform network.
		// Preserve that routing, but do not infer a non-cellular path for it.
		return &dialer, nil
	}
	iif, err := d.tfoNetworkInterface(base.LocalAddr)
	if err != nil {
		return nil, err
	}
	if iif == nil || iif.BindSocket == nil {
		// In particular, a missing platform record is not InterfaceTypeWIFI
		// just because that enum's zero value happens to be Wi-Fi.
		return &dialer, nil
	}
	switch iif.Type {
	case C.InterfaceTypeWIFI, C.InterfaceTypeEthernet, C.InterfaceTypeOther:
		dialer.DisableTFO = base.DisableTFO
	}
	// Bind even when TFO is suppressed. The type decision and socket must
	// refer to the same physical network. A lost network fails this dial;
	// it must not silently reroute a TFO SYN through a new cellular default.
	dialer.Control = control.Append(dialer.Control, func(_ string, _ string, conn syscall.RawConn) error {
		return control.Raw(conn, func(fd uintptr) error {
			return iif.BindSocket(int(fd))
		})
	})
	return &dialer, nil
}

func (d *DefaultDialer) tfoNetworkInterface(localAddr net.Addr) (*adapter.NetworkInterface, error) {
	interfaces := d.networkManager.NetworkInterfaces()
	var localIP netip.Addr
	if addr, ok := localAddr.(*net.TCPAddr); ok && !addr.IP.IsUnspecified() {
		localIP, _ = netip.AddrFromSlice(addr.IP)
		localIP = localIP.Unmap()
	}
	if d.tfoBindInterface != "" || localIP.IsValid() {
		for _, iif := range interfaces {
			if d.tfoBindInterface != "" && iif.Name != d.tfoBindInterface {
				continue
			}
			if localIP.IsValid() {
				matched := false
				for _, prefix := range iif.Addresses {
					if prefix.Addr().Unmap() == localIP {
						matched = true
						break
					}
				}
				if !matched {
					continue
				}
			}
			return &iif, nil
		}
		return nil, nil
	}
	selected, _ := selectInterfaces(d.networkManager, C.NetworkStrategyDefault, nil, nil)
	if len(selected) > 1 {
		return nil, E.New("`tcp_fast_open` requires a default network interface when multiple interfaces are available")
	}
	if len(selected) == 0 {
		return nil, nil
	}
	return &selected[0], nil
}
