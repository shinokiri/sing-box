package udpflow

import (
	"net/netip"
	"time"

	"github.com/sagernet/sing-tun"
)

type failureKey struct {
	binding *portBinding
	source  netip.AddrPort
	mapping tun.UDPMapping
}

// Keep only a retry deadline; failed queues and workers are still released.
// Established writes never consult this cache. Retrying is driven
// by the next packet after the deadline, with no new timer or background loop.
func (f *flow) closeFailed() {
	p := f.port
	p.access.Lock()
	if f.ctx.Err() == nil && (f.mapping == nil || f.mapping.Context().Err() == nil) {
		now := int64(time.Since(p.epoch))
		if len(p.failures) >= p.maxFlows {
			p.expireFailuresLocked(now)
		}
		if len(p.failures) >= p.maxFlows {
			var oldest failureKey
			var earliest int64
			for key, deadline := range p.failures {
				if earliest == 0 || deadline < earliest {
					oldest, earliest = key, deadline
				}
			}
			delete(p.failures, oldest)
		}
		p.failures[failureKey{f.binding, f.key, f.mapping}] = now + int64(failedAssociationBackoff)
	}
	f.closeLocked()
	p.access.Unlock()
	f.closeConn()
}

func (p *Port) expireFailuresLocked(now int64) {
	for key, deadline := range p.failures {
		if now >= deadline {
			delete(p.failures, key)
		}
	}
}
