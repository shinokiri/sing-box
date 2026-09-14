package dialer

import (
	"math"
	"syscall"
	"time"

	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/sys/unix"
)

func newTCPUserTimeout(timeout time.Duration) (control.Func, error) {
	// The kernel accepts a nonnegative signed int of milliseconds. Validate
	// before rounding so neither duration arithmetic nor a 32-bit int wraps.
	if timeout <= 0 || timeout > time.Duration(math.MaxInt32)*time.Millisecond {
		return nil, E.New("`tcp_user_timeout` must be positive and at most 2147483647ms")
	}
	milliseconds := int((timeout + time.Millisecond - 1) / time.Millisecond)
	return func(network, address string, conn syscall.RawConn) error {
		// DefaultDialer also copies this control chain into its UDP dialers.
		if N.NetworkName(network) != N.NetworkTCP {
			return nil
		}
		return control.Raw(conn, func(fd uintptr) error {
			if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, milliseconds); err != nil {
				return E.Cause(err, "set TCP_USER_TIMEOUT")
			}
			return nil
		})
	}, nil
}
