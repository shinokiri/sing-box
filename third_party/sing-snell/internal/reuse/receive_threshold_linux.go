//go:build linux

package reuse

import (
	"net"

	N "github.com/sagernet/sing/common/network"

	"golang.org/x/sys/unix"
)

// TCPReceiveThreshold reads the receive-window growth clamp of an established
// underlying TCP socket. It neither locks the receive buffer nor consumes data.
// The hint can differ from the advertised window when data is queued or other
// window clamps apply. Unsupported wrappers and failed queries have no hint.
func TCPReceiveThreshold(conn net.Conn) (threshold uint32, known bool) {
	_, raw := N.SyscallConnForRead(conn)
	if raw == nil {
		return 0, false
	}
	err := raw.Control(func(fd uintptr) {
		info, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
		const tcpEstablished = 1
		if err == nil && info.State == tcpEstablished && info.Rcv_ssthresh != 0 {
			threshold, known = info.Rcv_ssthresh, true
		}
	})
	if err != nil {
		return 0, false
	}
	return
}
