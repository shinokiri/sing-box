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
	// Cancellation invalidates the route without installing a drop tombstone.
	// Contexts are shared by a group's flows and are never canceled by the flow.
	RouteContexts []context.Context
	// RejectTimeout gives a rejection a fixed lifetime, without renewal on
	// traffic. Zero retains the normal idle timeout for policy rejections.
	RejectTimeout time.Duration
}

func (v FlowVerdict) RouteExpired() bool {
	return routeExpired(v.RouteContexts)
}

func routeExpired(contexts []context.Context) bool {
	for _, ctx := range contexts {
		if ctx.Err() != nil {
			return true
		}
	}
	return false
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

// PortWithUDPMapping carries socket associations, whose replies may come from
// a different peer endpoint. Ordinary IP ports retain exact-tuple filtering.
type PortWithUDPMapping interface {
	Port
	EndpointIndependentUDP() bool
	WriteUDPFlowPackets(packets []UDPFlowPacket) error
}

// UDPFlowPacket borrows Packet until WriteUDPFlowPackets returns. Flow captures
// the original tuple before batching, so a replacement at the same addresses
// cannot give queued data a new lifetime.
type UDPFlowPacket struct {
	Packet []byte
	Flow   UDPFlow
}

type UDPFlow interface {
	UDPMapping() UDPMapping
	IsActive() bool
}

// UDPMapping is one application endpoint's association lifetime. Implementations
// must have comparable identity (the dispatcher supplies a pointer). A port must
// capture it when dialing; an old connection must never acquire a new mapping
// merely because its numeric selector was reused. ReturnPacket reports whether
// a reply had a live owner, so discarded traffic need not renew idle timeouts.
type UDPMapping interface {
	Context() context.Context
	IsActive() bool
	ReturnPacket(packet []byte) bool
}

// ReturnWithUDPMapping supplies association handles to PortWithUDPMapping.
// Ordinary IP ports continue to use ReturnPackets directly.
type ReturnWithUDPMapping interface {
	Return
	UDPMapping(source netip.AddrPort) UDPMapping
}

type Return interface {
	ReturnHeadroom() int
	ReturnPackets(packets [][]byte) [][]byte
}
