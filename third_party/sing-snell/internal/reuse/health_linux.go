//go:build linux

package reuse

import (
	"net"

	N "github.com/sagernet/sing/common/network"
	"golang.org/x/sys/unix"
)

// TCPReceiveState obtains the existing receive-window hint and the transport
// state in one TCP_INFO query. It neither reads payload nor changes deadlines.
// Unknown wrappers retain portable behavior; this cannot prevent a later close.
func TCPReceiveState(conn net.Conn) (threshold uint32, known bool, reusable bool) {
	_, raw := N.SyscallConnForRead(conn)
	if raw == nil {
		return 0, false, true
	}
	reusable = true
	err := raw.Control(func(fd uintptr) {
		info, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
		if err == nil {
			const tcpEstablished = 1
			reusable = info.State == tcpEstablished
			if reusable && info.Rcv_ssthresh != 0 {
				threshold, known = info.Rcv_ssthresh, true
			}
		}
	})
	if err != nil {
		return 0, false, false
	}
	return
}
