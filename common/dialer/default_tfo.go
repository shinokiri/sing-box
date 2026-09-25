package dialer

import (
	"context"
	"net"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

func checkTFOInterfaceOptions(strategy *C.NetworkStrategy, interfaceType, fallbackInterfaceType []C.InterfaceType) error {
	if strategy != nil && *strategy != C.NetworkStrategyDefault || len(interfaceType) != 0 || len(fallbackInterfaceType) != 0 {
		return E.New("`tcp_fast_open` does not support `network_strategy`, `network_type` or `fallback_network_type` overrides (including route defaults)")
	}
	return nil
}

func (d *DefaultDialer) dialTFOInterface(ctx context.Context, network string, address M.Socksaddr, strategy *C.NetworkStrategy, interfaceType, fallbackInterfaceType []C.InterfaceType) (net.Conn, error) {
	if err := checkTFOInterfaceOptions(strategy, interfaceType, fallbackInterfaceType); err != nil {
		return nil, err
	}
	if !address.IsValid() {
		return nil, E.New("invalid address")
	} else if address.IsDomain() {
		return nil, E.New("domain not resolved")
	}
	interfaces, _ := selectInterfaces(d.networkManager, C.NetworkStrategyDefault, nil, nil)
	if len(interfaces) == 0 {
		return nil, E.New("no available network interface")
	} else if len(interfaces) != 1 {
		// A lazy TFO connection cannot be raced before its first write. Racing
		// writes instead could send application data on more than one socket.
		return nil, E.New("`tcp_fast_open` requires a default network interface when multiple interfaces are available")
	}
	if d.androidTFO {
		// Select and bind the physical network again on the first write, not
		// when the lazy connection is returned to the caller.
		if address.IsIPv6() {
			return d.dialSlowContext(&d.dialer6, ctx, network, address)
		}
		return d.dialSlowContext(&d.dialer4, ctx, network, address)
	}
	tcpDialer := d.dialer4
	if address.IsIPv6() {
		tcpDialer = d.dialer6
	}
	iif := interfaces[0]
	defaultInterface := d.networkManager.InterfaceMonitor().DefaultInterface()
	if defaultInterface == nil || iif.Index != defaultInterface.Index {
		tcpDialer.Control = control.Append(tcpDialer.Control, control.BindToInterface(nil, iif.Name, iif.Index))
	}
	// Keep the complete TFO dialer, including platform ProtectFunc and any
	// socket controls. The ordinary interface dialer discards the TFO wrapper.
	return dialSlowContext(&tcpDialer, ctx, network, address, d.netns)
}
