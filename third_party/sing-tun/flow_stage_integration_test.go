//go:build (linux && !android) || (darwin && !ios) || windows

package tun

import (
	"context"
	"net/netip"
)

// Exercise the real kernel tests through the asynchronous routing interface
// used by sing-box, including multi-queue TCP and UDP setup and teardown.
func (f *kernelStackFixture) JudgeFlowContext(ctx context.Context, network uint8, source, destination netip.AddrPort, packet []byte) FlowVerdict {
	if ctx.Err() != nil {
		return FlowVerdict{Action: ActionDrop}
	}
	return f.JudgeFlow(network, source, destination, packet)
}
