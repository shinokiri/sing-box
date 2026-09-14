//go:build !linux

package dialer

import (
	"time"

	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
)

func newTCPUserTimeout(timeout time.Duration) (control.Func, error) {
	return nil, E.New("`tcp_user_timeout` is only supported on Linux and Android")
}
