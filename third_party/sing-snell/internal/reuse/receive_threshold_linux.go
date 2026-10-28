//go:build linux

package reuse

import "net"

// TCPReceiveThreshold reads the receive-window growth clamp of an established
// underlying TCP socket. It neither locks the receive buffer nor consumes data.
// The hint can differ from the advertised window when data is queued or other
// window clamps apply. Unsupported wrappers and failed queries have no hint.
func TCPReceiveThreshold(conn net.Conn) (threshold uint32, known bool) {
	threshold, known, _ = TCPReceiveState(conn)
	return
}
