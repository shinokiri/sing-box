//go:build linux

package reuse

import (
	"net"
	"syscall"

	"github.com/sagernet/sing/common"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/sys/unix"
)

// TCPReceiveState obtains the existing receive-window hint and the transport
// state in one TCP_INFO query. It neither reads payload nor changes deadlines.
// Unknown wrappers retain portable behavior; this cannot prevent a later close.
func TCPReceiveState(conn net.Conn) (uint32, bool, bool) {
	raw := tcpMetadataConn(conn)
	if raw == nil {
		return 0, false, true
	}
	// Keep the query result in one callback allocation, instead of letting
	// each returned field escape separately.
	var snapshot struct {
		threshold uint32
		status    uint8
	}
	const (
		closed   = 1
		measured = 2
	)
	err := raw.Control(func(fd uintptr) {
		info, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
		if err == nil {
			const tcpEstablished = 1
			if info.State != tcpEstablished {
				snapshot.status = closed
			} else if info.Rcv_ssthresh != 0 {
				snapshot.threshold, snapshot.status = info.Rcv_ssthresh, measured
			}
		}
	})
	if err != nil {
		return 0, false, false
	}
	return snapshot.threshold, snapshot.status == measured, snapshot.status != closed
}

func tcpMetadataConn(conn net.Conn) syscall.RawConn {
	_, raw := N.SyscallConnForRead(conn)
	if raw != nil {
		return raw
	}
	// SFA's trackedConn implements syscall.Conn, but its method returns an
	// error when the immediate upstream is a deferred TFO wrapper. The read
	// helper stops there. For metadata only, follow the wrappers to the live
	// socket, without reading data or initiating a deferred connection.
	for depth := 0; conn != nil && depth < 8; depth++ {
		if reader, ok := conn.(N.ReaderWithUpstream); !ok || !reader.ReaderReplaceable() {
			break
		}
		upstream, ok := conn.(common.WithUpstream)
		if !ok {
			break
		}
		conn, _ = upstream.Upstream().(net.Conn)
		if socket, ok := conn.(syscall.Conn); ok {
			raw, err := socket.SyscallConn()
			if err == nil && raw != nil {
				return raw
			}
		}
	}
	return nil
}
