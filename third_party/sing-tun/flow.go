package tun

import (
	"context"
	"net/netip"
	"time"
)

// ContextFlowHandler permits the dispatcher to resolve a new flow away from
// the TUN reader. The handler must honor cancellation and may use firstPacket
// only until it returns. Existing handlers retain synchronous dispatch.
type ContextFlowHandler interface {
	JudgeFlowContext(ctx context.Context, network uint8, source netip.AddrPort, destination netip.AddrPort, firstPacket []byte) FlowVerdict
}

type FlowVerdict struct {
	Action      FlowAction
	Port        Port
	Destination netip.AddrPort
	UDPTimeout  time.Duration
	NewTracker  func() FlowTracker
}

type FlowAction uint8

const (
	ActionAccept FlowAction = iota
	ActionFlow
	ActionReject
	ActionDrop
	ActionBypass
	ActionHijackDNS
)

type FlowTracker interface {
	AttachFlow(handle FlowHandle)
	CountForward(n int)
	CountReverse(n int)
	FlowEstablished()
	CloseFlow(reason FlowCloseReason)
}

type FlowHandle interface {
	CloseFlow()
}

type FlowCloseReason uint8

const (
	FlowCloseReset FlowCloseReason = iota
	FlowCloseFinished
	FlowCloseTimeout
)

func (r FlowCloseReason) String() string {
	switch r {
	case FlowCloseFinished:
		return "finished"
	case FlowCloseTimeout:
		return "idle timeout"
	default:
		return "connection reset"
	}
}

type Port interface {
	PortAddresses() (v4 netip.Addr, v6 netip.Addr)
	PortMTU() uint32
	AttachReturn(returnPath Return) error
	DetachReturn(returnPath Return) error
	WritePackets(packets [][]byte) error
}

type PortWithSelectorRange interface {
	Port
	PortSelectorRange() (start uint16, count uint16)
}

type Return interface {
	ReturnHeadroom() int
	ReturnPackets(packets [][]byte) [][]byte
}
