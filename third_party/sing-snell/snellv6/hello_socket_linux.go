//go:build linux

package snellv6

import (
	"net"
	"syscall"

	"github.com/sagernet/sing/common"
	"golang.org/x/sys/unix"
)

// Before a deferred TFO write, TCP_INFO/TCP_MAXSEG can report a placeholder536.
// Only an established socket supplies a negotiated MSS suitable for caching.
func helloSocketCapacity(conn net.Conn) (negotiated, routeLimit int) {
	for depth := 0; conn != nil && depth < 8; depth++ {
		if socket, ok := conn.(syscall.Conn); ok {
			raw, err := socket.SyscallConn()
			if err == nil {
				_ = raw.Control(func(fd uintptr) {
					level, option, headers := unix.IPPROTO_IP, unix.IP_MTU, 80
					if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok && addr.IP.To4() == nil {
						level, option, headers = unix.IPPROTO_IPV6, unix.IPV6_MTU, 100
					}
					if mtu, err := unix.GetsockoptInt(int(fd), level, option); err == nil {
						routeLimit = mtu - headers
					}
					info, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
					if err != nil || info.State != 1 { // Linux TCP_ESTABLISHED
						return
					}
					negotiated = int(info.Snd_mss) - 40
					if info.Options&1 != 0 {
						negotiated += 12
					}
					if routeLimit > 0 {
						negotiated = min(negotiated, routeLimit)
					}
				})
				return
			}
			// SFA's trackedConn exposes SyscallConn but cannot forward it
			// through a delayed TFO connection. Follow Upstream to its socket.
		}
		u, ok := conn.(common.WithUpstream)
		if !ok {
			return
		}
		conn, _ = u.Upstream().(net.Conn)
	}
	return
}
