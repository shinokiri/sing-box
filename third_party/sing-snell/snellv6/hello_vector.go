package snellv6

import (
	"net"

	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"
)

// Keep an already available application prefix in the same first record.
// Otherwise the normal vector path initializes the handshake with only its first
// buffer, leaving the rest behind another TCP round trip. This copies at most
// one SYN-sized batch, only on a new hello-framed physical connection; it never
// waits for additional data. A large vector keeps its uncopied suffix, and
// later/ordinary vector writes keep their normal path.
func gatherHelloFirstVector(physical net.Conn, writer any, buffers []*buf.Buffer, requestLen int) []*buf.Buffer {
	if len(buffers) < 2 {
		return buffers
	}
	limit, _ := helloFirstPayloadLimit(physical)
	limit -= requestLen
	if limit <= 0 {
		return buffers
	}
	total, nonempty := 0, 0
	for _, b := range buffers {
		total += min(b.Len(), limit-total)
		if !b.IsEmpty() {
			nonempty++
		}
		if total == limit {
			break
		}
	}
	if nonempty < 2 {
		return buffers
	}
	front, rear := N.CalculateFrontHeadroom(writer), N.CalculateRearHeadroom(writer)
	joined := buf.NewSize(front + total + rear)
	joined.Resize(front, 0)
	at := 0
	for joined.Len() < total {
		b := buffers[at]
		n := min(b.Len(), total-joined.Len())
		_, _ = joined.Write(b.Bytes()[:n])
		if n < b.Len() {
			b.Advance(n)
			break
		}
		b.Release()
		at++
	}
	return append([]*buf.Buffer{joined}, buffers[at:]...)
}
