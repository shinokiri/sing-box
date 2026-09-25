package daemon

import "github.com/sagernet/sing-box/adapter"

// Reserve every target before submitting work to the bounded test queue.
// Otherwise the queued nodes would continue displaying their previous result.
func urlTestTargets(manager adapter.OutboundManager, outbound adapter.Outbound) []string {
	var targets []string
	seen := make(map[string]bool)
	var collect func(adapter.Outbound)
	collect = func(outbound adapter.Outbound) {
		tag := outbound.Tag()
		if seen[tag] {
			return
		}
		seen[tag] = true
		targets = append(targets, tag)
		if group, ok := outbound.(adapter.OutboundGroup); ok {
			for _, memberTag := range group.All() {
				if member, loaded := manager.Outbound(memberTag); loaded {
					collect(member)
				}
			}
		}
	}
	collect(outbound)
	return targets
}
