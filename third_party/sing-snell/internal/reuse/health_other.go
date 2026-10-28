//go:build !linux

package reuse

import "net"

func TCPReceiveState(net.Conn) (uint32, bool, bool) { return 0, false, true }
