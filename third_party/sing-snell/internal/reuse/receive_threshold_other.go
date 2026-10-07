//go:build !linux

package reuse

import "net"

func TCPReceiveThreshold(net.Conn) (uint32, bool) {
	return 0, false
}
