package dialer

import (
	"errors"
	"fmt"
	"syscall"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/control"
)

type networkBinder func(fd uintptr, networkHandle uint64) error

var errNetworkBinding = errors.New("bind Android network")

func networkControl(bind networkBinder, handle uint64) control.Func {
	return func(network, address string, conn syscall.RawConn) error {
		err := control.Raw(conn, func(fd uintptr) error { return bind(fd, handle) })
		if err != nil {
			// Do not let the legacy EPERM workaround retry on an unbound socket.
			return fmt.Errorf("%w %d: %w", errNetworkBinding, handle, err)
		}
		return nil
	}
}

func (d *DefaultDialer) interfaceControl(iif adapter.NetworkInterface, defaultInterface *control.Interface) control.Func {
	if d.bindNetwork != nil && iif.NetworkHandle != 0 {
		return networkControl(d.bindNetwork, iif.NetworkHandle)
	}
	if defaultInterface == nil || iif.Index != defaultInterface.Index {
		return control.BindToInterface(nil, iif.Name, iif.Index)
	}
	return nil
}
