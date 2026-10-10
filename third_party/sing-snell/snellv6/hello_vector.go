package snellv6

import (
	"net"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"
)

// Keep an already available small application vector in the same first record.
// Otherwise the normal vector path initializes the handshake with only its first
// buffer, leaving the rest behind another TCP round trip. This copies at most
// one SYN-sized batch, only on a new hello-framed physical connection; it never
// waits for additional data or changes large/later/ordinary vector writes.
func gatherHelloFirstVector(physical net.Conn, writer any, buffers []*buf.Buffer, requestLen int) []*buf.Buffer {
	if len(buffers) < 2 {
		return buffers
	}
	var hello *helloConn
	for depth := 0; physical != nil && depth < 8; depth++ {
		if c, ok := physical.(*helloConn); ok {
			hello = c
			break
		}
		u, ok := physical.(common.WithUpstream)
		if !ok {
			return buffers
		}
		physical, _ = u.Upstream().(net.Conn)
	}
	if hello == nil || hello.sent.Load() {
		return buffers
	}
	budget, _ := hello.transport.budget(hello.Conn, hello.endpoint, hello.generation)
	limit := budget - (85 + 1 + saltLen + snell.HeaderCipherLen + snell.AEADTagLen) - requestLen
	total, nonempty := 0, 0
	for _, b := range buffers {
		if b.Len() > limit-total {
			return buffers
		}
		total += b.Len()
		if !b.IsEmpty() {
			nonempty++
		}
	}
	if nonempty < 2 {
		return buffers
	}
	front, rear := N.CalculateFrontHeadroom(writer), N.CalculateRearHeadroom(writer)
	joined := buf.NewSize(front + total + rear)
	joined.Resize(front, 0)
	for _, b := range buffers {
		_, _ = joined.Write(b.Bytes())
	}
	buf.ReleaseMulti(buffers)
	return []*buf.Buffer{joined}
}
