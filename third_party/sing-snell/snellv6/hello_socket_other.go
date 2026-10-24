//go:build !linux

package snellv6

import "net"

func helloSocketCapacity(net.Conn) (int, int) { return 0, 0 }
