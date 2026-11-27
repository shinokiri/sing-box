package tun

import (
	"context"
	"encoding/binary"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-tun/gtcpip"
	"github.com/sagernet/sing-tun/gtcpip/checksum"
	"github.com/sagernet/sing-tun/gtcpip/header"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

const (
	tcpEstablishedTimeout = 2*time.Hour + 4*time.Minute
	tcpTransitoryTimeout  = 4 * time.Minute
	tcpClosingTimeout     = 10 * time.Second

	defaultUDPTimeout = 5 * time.Minute

	defaultICMPTimeout = time.Minute

	flowTombstoneTimeout = 4 * time.Minute

	flowTableCapacity = 16384

	flowSweepInterval = 30 * time.Second
	flowSweepLimit    = flowTableCapacity / int(flowTombstoneTimeout/flowSweepInterval)
)

type ForwardWriteback interface {
	ReturnHeadroom() int
	WriteReturnPackets(packets [][]byte) error
}

type ForwardFrameMeta struct {
	needsChecksum    bool
	dataValid        bool
	acceptedFragment bool
	checksumStart    uint16
	checksumOffset   uint16
	gsoType          uint8
	gsoSize          uint16
}

func (m *ForwardFrameMeta) completeChecksum(raw []byte) {
	if !m.needsChecksum {
		return
	}
	m.needsChecksum = false
	checksumAt := int(m.checksumStart) + int(m.checksumOffset)
	if int(m.checksumStart) >= len(raw) || checksumAt+2 > len(raw) {
		return
	}
	initial := binary.BigEndian.Uint16(raw[checksumAt:])
	raw[checksumAt], raw[checksumAt+1] = 0, 0
	transportChecksum := ^checksum.Checksum(raw[m.checksumStart:], initial)
	if transportChecksum == 0 {
		transportChecksum = 0xffff
	}
	binary.BigEndian.PutUint16(raw[checksumAt:], transportChecksum)
}

type flowEntry struct {
	action   FlowAction
	deadline int64
	idle     time.Duration // Zero for a fixed rejection deadline.
	flow     *forwardFlow
	verdict  FlowVerdict
}

type forwardFlow struct {
	nat           *portNAT
	mapping       *natMapping
	selectorKey   natSelectorKey
	owner         *ForwardDispatcher
	reverseKey    flowKey
	forwardRule   rewriteRule
	reverseRule   rewriteRule
	effectiveMTU  uint32
	protocol      uint8
	udpTimeout    time.Duration
	tracker       FlowTracker
	routeContexts []context.Context
	udpMapping    *udpMapping
	// Intrusive association list, protected by nat.udpAccess. Removed tuples
	// leave this list even while their peer aliases remain reserved.
	udpPrev, udpNext *forwardFlow

	clientAddress            netip.Addr
	clientSelector           uint16
	clientDestinationAddress netip.Addr
	clientDestinationPort    uint16
	serverAddress            netip.Addr
	dnatAddress              bool
	dnatPort                 bool

	finForward  atomic.Bool
	established atomic.Bool
	finReverse  atomic.Bool
	reported    atomic.Bool
	closed      atomic.Bool
	aborted     atomic.Bool
	lastReverse atomic.Int64
}

func (f *forwardFlow) report(reason FlowCloseReason) {
	if !f.reported.CompareAndSwap(false, true) {
		return
	}
	if f.tracker != nil {
		f.tracker.CloseFlow(reason)
	}
}

func (f *forwardFlow) close(reason FlowCloseReason) {
	if !f.closed.CompareAndSwap(false, true) {
		return
	}
	f.report(reason)
}

func (f *forwardFlow) CloseFlow() {
	f.aborted.Store(true)
	f.close(FlowCloseReset)
}

func (f *forwardFlow) observeReverse(packet *forwardPacket, now int64) {
	f.lastReverse.Store(now)
	if packet.protocol != uint8(header.TCPProtocolNumber) {
		return
	}
	if f.established.CompareAndSwap(false, true) && f.tracker != nil {
		f.tracker.FlowEstablished()
	}
	if packet.tcpFlags&header.TCPFlagRst != 0 {
		f.close(FlowCloseReset)
		return
	}
	if packet.tcpFlags&header.TCPFlagFin != 0 {
		f.finReverse.Store(true)
	} else if f.finReverse.Load() && f.finForward.Load() {
		f.report(FlowCloseFinished)
	}
}

type ForwardDispatcher struct {
	epoch          time.Time
	handler        Handler
	writeback      ForwardWriteback
	logger         logger.Logger
	udpTimeout     time.Duration
	udpMapping     NATMapping
	udpFiltering   NATFiltering
	icmpTimeout    time.Duration
	access         sync.Mutex
	root           *ForwardDispatcher
	stagesAccess   sync.Mutex
	stages         []*ForwardStage
	portsAccess    sync.Mutex
	returnsAccess  sync.Mutex
	returns        atomic.Pointer[[]*portReturn]
	identification atomic.Uint32
	mtu            uint32
	fragments      fragmentTable
	portOutput     stagePortOutput

	table     map[flowKey]*flowEntry
	lastSweep int64
	ports     map[Port]*portReturn

	stagedPorts    []stagedPort
	writebackBatch [][]byte
	returnPath     *forwardReturn
	exhaustedLogAt int64

	segmentBuffers [][]byte
	segmentSizes   []int
	segmentUsed    int

	async *asyncFlowState
}

func addrToTCPIP(addr netip.Addr) tcpip.Address {
	if addr.Is4() {
		return tcpip.AddrFrom4(addr.As4())
	}
	return tcpip.AddrFrom16(addr.As16())
}

func NewForwardDispatcher(handler Handler, writeback ForwardWriteback, logger logger.Logger, udpTimeout time.Duration, icmpTimeout time.Duration) *ForwardDispatcher {
	// Preserve exact-peer filtering for legacy L3 callers. Socket-style proxy
	// ports still use their captured endpoint-independent UDP associations.
	return NewForwardDispatcherWithOptions(handler, writeback, logger, UDPNatOptions{
		Timeout: udpTimeout, Mapping: NATMappingAddressAndPortDependent, Filtering: NATFilteringAddressAndPortDependent,
	}, icmpTimeout)
}

func NewForwardDispatcherWithOptions(handler Handler, writeback ForwardWriteback, logger logger.Logger, udpOptions UDPNatOptions, icmpTimeout time.Duration) *ForwardDispatcher {
	dispatcher := &ForwardDispatcher{
		epoch:        time.Now(),
		handler:      handler,
		writeback:    writeback,
		logger:       logger,
		udpTimeout:   udpOptions.Timeout,
		udpMapping:   udpOptions.Mapping,
		udpFiltering: udpOptions.Filtering,
		icmpTimeout:  icmpTimeout,
		table:        make(map[flowKey]*flowEntry),
		ports:        make(map[Port]*portReturn),
	}
	if dispatcher.udpTimeout <= 0 {
		dispatcher.udpTimeout = defaultUDPTimeout
	}
	if dispatcher.icmpTimeout <= 0 {
		dispatcher.icmpTimeout = defaultICMPTimeout
	}
	dispatcher.returns.Store(new([]*portReturn))
	dispatcher.portOutput.stage = dispatcher
	dispatcher.root = dispatcher
	dispatcher.returnPath = &forwardReturn{dispatcher: dispatcher}
	return dispatcher
}

func (d *ForwardDispatcher) now() int64 {
	return int64(time.Since(d.epoch))
}

func (d *ForwardDispatcher) Close() {
	if d == nil {
		return
	}
	root := d.root
	if !root.returnPath.closed.CompareAndSwap(false, true) {
		return
	}
	root.resetStages()
	root.portsAccess.Lock()
	returns := make([]*portReturn, 0, len(root.ports))
	for _, returnPath := range root.ports {
		returns = append(returns, returnPath)
	}
	root.portsAccess.Unlock()
	for _, returnPath := range returns {
		returnPath.nat.port.DetachReturn(returnPath)
		releasePortNAT(returnPath.nat)
	}
}

func (d *ForwardDispatcher) Dispatch(packet []byte) bool {
	if d == nil || d.returnPath.closed.Load() {
		return false
	}
	parsed, ok := parseForwardPacket(packet)
	if !ok {
		return false
	}
	return d.dispatch(packet, &parsed)
}

func (d *ForwardDispatcher) dispatch(packet []byte, parsed *forwardPacket) bool {
	if parsed.fragment && parsed.fragmentInfo.offset != 0 {
		return d.dispatchFragment(packet, parsed)
	}
	if !parsed.hasFlow {
		return false
	}
	d.access.Lock()
	if d.returnPath.closed.Load() {
		d.access.Unlock()
		return false
	}
	key := parsed.flowKey()
	if d.async != nil {
		if pending := d.async.pending[key]; pending != nil {
			if d.enqueuePendingPacket(pending, packet) && parsed.fragment {
				d.fragments.pend(parsed.fragmentKey(), parsed.fragmentInfo, d.now())
			}
			d.access.Unlock()
			return true
		}
	}
	now := d.now()
	entry, loaded := d.table[key]
	if loaded && d.entryExpired(entry, now) {
		d.removeEntry(key, entry, FlowCloseTimeout)
		loaded = false
	}
	if loaded {
		handled := d.handleHit(key, entry, parsed, packet, now)
		if parsed.fragment {
			d.resolveFragments(parsed, key, handled, now)
		}
		d.access.Unlock()
		return handled
	}
	if parsed.protocol == uint8(header.TCPProtocolNumber) &&
		(parsed.tcpFlags&header.TCPFlagSyn == 0 || parsed.tcpFlags&header.TCPFlagAck != 0) {
		d.access.Unlock()
		return false
	}
	if d.async != nil {
		d.startPendingFlow(key, packet)
		if parsed.fragment && d.async.pending[key] != nil {
			d.fragments.pend(parsed.fragmentKey(), parsed.fragmentInfo, now)
		}
		d.access.Unlock()
		return true
	}
	d.access.Unlock()
	return d.judgeAndInstall(key, parsed, packet)
}

func (d *ForwardDispatcher) handleHit(key flowKey, entry *flowEntry, packet *forwardPacket, raw []byte, now int64) bool {
	switch entry.action {
	case ActionFlow:
		flow := entry.flow
		if packet.fragment && flow.udpMapping != nil {
			// Socket ports need the entire UDP datagram, which the stack reassembles.
			return false
		}
		if flow.closed.Load() {
			d.tombstoneEntry(entry, now)
			return true
		}
		var flowFinished bool
		if packet.protocol == uint8(header.TCPProtocolNumber) {
			if packet.tcpFlags&header.TCPFlagRst != 0 {
				d.forwardToPort(flow, packet, raw)
				flow.close(FlowCloseReset)
				d.tombstoneEntry(entry, now)
				return true
			}
			if packet.tcpFlags&header.TCPFlagFin != 0 {
				flow.finForward.Store(true)
			} else if flow.finForward.Load() && flow.finReverse.Load() {
				flowFinished = true
			}
		}
		entry.idle = d.flowIdle(flow)
		entry.deadline = now + int64(entry.idle)
		d.forwardToPort(flow, packet, raw)
		if flowFinished {
			flow.report(FlowCloseFinished)
		}
		return true
	case ActionAccept:
		packet.verdict = entry.verdict
		if packet.protocol == uint8(header.TCPProtocolNumber) {
			if packet.tcpFlags&header.TCPFlagSyn == 0 {
				d.removeEntry(key, entry, FlowCloseReset)
				return false
			}
		}
		entry.deadline = now + int64(entry.idle)
		return false
	case ActionReject:
		if entry.idle > 0 {
			entry.deadline = now + int64(entry.idle)
		}
		d.stageReject(packet)
		return true
	default:
		entry.deadline = now + int64(entry.idle)
		return true
	}
}

func (d *ForwardDispatcher) judgeAndInstall(key flowKey, packet *forwardPacket, raw []byte) bool {
	var firstPacket []byte
	if packet.protocol == uint8(header.UDPProtocolNumber) {
		firstPacket = header.UDP(packet.transport).Payload()
	}
	verdict := d.handler.JudgeFlow(packet.protocol, packet.source, packet.destination, firstPacket)
	if verdict.Action == ActionHijackDNS && !packet.fragment && packet.protocol == uint8(header.UDPProtocolNumber) {
		if d.returnPath.closed.Load() {
			return false
		}
		d.hijackDNSPacket(packet)
		return true
	}
	d.access.Lock()
	defer d.access.Unlock()
	if d.returnPath.closed.Load() {
		return false
	}
	handled := d.installVerdict(key, packet, raw, verdict)
	if packet.fragment {
		d.resolveFragments(packet, key, handled, d.now())
	}
	return handled
}

// Caller holds access. Pending resolutions use the same routing/NAT logic as
// synchronous dispatch. Callers handle UDP DNS hijacking outside access: a
// cached DNS answer can synchronously write to the TUN device.
func (d *ForwardDispatcher) installVerdict(key flowKey, packet *forwardPacket, raw []byte, verdict FlowVerdict) bool {
	if verdict.RouteExpired() {
		return true
	}
	now := d.now()
	if existing := d.table[key]; existing != nil {
		if d.entryExpired(existing, now) {
			d.removeEntry(key, existing, FlowCloseTimeout)
		} else {
			return d.handleHit(key, existing, packet, raw, now)
		}
	}
	if verdict.Action == ActionBypass && verdict.Port != nil {
		verdict.Action = ActionFlow
	}
	switch verdict.Action {
	case ActionFlow:
		if verdict.Port != nil {
			flow, result := d.createFlow(packet, verdict)
			if result == createFlowOK {
				entry := &flowEntry{action: ActionFlow, flow: flow, idle: d.flowIdle(flow)}
				entry.deadline = now + int64(entry.idle)
				d.insertEntry(key, entry, now)
				if packet.fragment && flow.udpMapping != nil {
					return false
				}
				d.forwardToPort(flow, packet, raw)
				return true
			}
			if result == createFlowExhausted {
				if now-d.exhaustedLogAt >= int64(exhaustedLogInterval) {
					d.exhaustedLogAt = now
					d.logger.Warn("port selector range exhausted, rejecting flow to ", packet.destination)
				}
				d.installSimple(key, ActionReject, packet.protocol, now)
				d.stageReject(packet)
				return true
			}
		}
		d.installAccept(key, packet, verdict, now)
		return false
	case ActionReject:
		if verdict.RejectTimeout > 0 {
			d.insertEntry(key, &flowEntry{action: ActionReject, deadline: now + int64(verdict.RejectTimeout)}, now)
		} else {
			d.installSimple(key, ActionReject, packet.protocol, now)
		}
		d.stageReject(packet)
		return true
	case ActionDrop:
		d.installSimple(key, ActionDrop, packet.protocol, now)
		return true
	default:
		d.installAccept(key, packet, verdict, now)
		return false
	}
}

func (d *ForwardDispatcher) installAccept(key flowKey, packet *forwardPacket, verdict FlowVerdict, now int64) {
	entry := &flowEntry{action: ActionAccept, idle: d.idleTimeout(packet.protocol, false), verdict: verdict}
	entry.deadline = now + int64(entry.idle)
	packet.verdict = verdict
	d.insertEntry(key, entry, now)
}

func (d *ForwardDispatcher) installSimple(key flowKey, action FlowAction, protocol uint8, now int64) {
	entry := &flowEntry{action: action, idle: d.idleTimeout(protocol, false)}
	entry.deadline = now + int64(entry.idle)
	d.insertEntry(key, entry, now)
}

func (d *ForwardDispatcher) idleTimeout(protocol uint8, established bool) time.Duration {
	switch protocol {
	case uint8(header.TCPProtocolNumber):
		if established {
			return tcpEstablishedTimeout
		}
		return tcpTransitoryTimeout
	case uint8(header.UDPProtocolNumber):
		return d.udpTimeout
	default:
		return d.icmpTimeout
	}
}

func (d *ForwardDispatcher) flowIdle(flow *forwardFlow) time.Duration {
	if flow.protocol == uint8(header.TCPProtocolNumber) && flow.finForward.Load() && flow.finReverse.Load() {
		return tcpClosingTimeout
	}
	if flow.udpTimeout > 0 {
		return flow.udpTimeout
	}
	established := flow.established.Load() && !flow.finForward.Load() && !flow.finReverse.Load()
	return d.idleTimeout(flow.protocol, established)
}

type createFlowResult uint8

const (
	createFlowOK createFlowResult = iota
	createFlowUnsupported
	createFlowExhausted
)

const exhaustedLogInterval = 5 * time.Second

func (d *ForwardDispatcher) createFlow(packet *forwardPacket, verdict FlowVerdict) (*forwardFlow, createFlowResult) {
	var portAddress netip.Addr
	inet4Address, inet6Address := verdict.Port.PortAddresses()
	if packet.ipVersion == 6 {
		portAddress = inet6Address
	} else {
		portAddress = inet4Address
	}
	if !portAddress.IsValid() {
		return nil, createFlowUnsupported
	}
	effectiveMTU := verdict.Port.PortMTU()
	if mtu := d.root.mtu; mtu != 0 && (effectiveMTU == 0 || mtu < effectiveMTU) {
		effectiveMTU = mtu
	}
	if packet.ipVersion == 6 && effectiveMTU != 0 && effectiveMTU < header.IPv6MinimumMTU {
		return nil, createFlowUnsupported
	}
	isICMP := isICMPProtocol(packet.protocol)
	clientDestinationAddress := packet.destination.Addr()
	clientDestinationPort := packet.destination.Port()
	serverAddress := clientDestinationAddress
	serverPort := clientDestinationPort
	if verdict.Destination.Addr().IsValid() {
		serverAddress = verdict.Destination.Addr()
		if serverAddress.Is4() != clientDestinationAddress.Is4() {
			return nil, createFlowUnsupported
		}
	}
	if verdict.Destination.Port() != 0 && !isICMP {
		serverPort = verdict.Destination.Port()
	}
	nat := d.natFor(verdict.Port)
	if nat == nil {
		return nil, createFlowUnsupported
	}
	nat.allocateAccess.Lock()
	defer nat.allocateAccess.Unlock()
	server := netip.AddrPortFrom(serverAddress, serverPort)
	natAddress := portAddress
	if nat.routed {
		natAddress = packet.source.Addr()
	}
	reservation, reserved := nat.reserve(d.root, packet.protocol, natAddress, packet.source, server, packet.destination)
	if !reserved {
		rangedPort, isRanged := portCapability[PortWithSelectorRange](verdict.Port)
		if isRanged && rangedPort.ExpandSelectorRanges(packet.protocol) {
			reservation, reserved = nat.reserve(d.root, packet.protocol, natAddress, packet.source, server, packet.destination)
		}
		if !reserved {
			return nil, createFlowExhausted
		}
	}
	var udpTimeout time.Duration
	if packet.protocol == uint8(header.UDPProtocolNumber) {
		udpTimeout = verdict.UDPTimeout
	}
	flow := &forwardFlow{
		nat:                      nat,
		owner:                    d,
		effectiveMTU:             effectiveMTU,
		protocol:                 packet.protocol,
		udpTimeout:               udpTimeout,
		routeContexts:            verdict.RouteContexts,
		clientAddress:            packet.source.Addr(),
		clientSelector:           packet.source.Port(),
		clientDestinationAddress: clientDestinationAddress,
		clientDestinationPort:    clientDestinationPort,
		serverAddress:            serverAddress,
		dnatAddress:              serverAddress != clientDestinationAddress,
		dnatPort:                 serverPort != clientDestinationPort && !isICMP,
	}
	flow.forwardRule = rewriteRule{rewriteSourcePort: true}
	if !nat.routed {
		flow.forwardRule.sourceAddress = addrToTCPIP(portAddress)
	}
	if flow.dnatAddress {
		flow.forwardRule.destinationAddress = addrToTCPIP(serverAddress)
	}
	if flow.dnatPort {
		flow.forwardRule.destinationPort = serverPort
		flow.forwardRule.rewriteDestinationPort = true
	}
	flow.reverseRule = rewriteRule{
		destinationAddress:     addrToTCPIP(flow.clientAddress),
		destinationPort:        flow.clientSelector,
		rewriteDestinationPort: true,
	}
	if flow.dnatAddress {
		flow.reverseRule.sourceAddress = addrToTCPIP(clientDestinationAddress)
	}
	if flow.dnatPort {
		flow.reverseRule.sourcePort = clientDestinationPort
		flow.reverseRule.rewriteSourcePort = true
	}
	if verdict.NewTracker != nil {
		flow.tracker = verdict.NewTracker()
		if flow.tracker != nil {
			flow.tracker.AttachFlow(flow)
		}
	}
	nat.publish(flow, reservation)
	return flow, createFlowOK
}

func (d *ForwardDispatcher) natFor(port Port) *portNAT {
	if d.root != d {
		return d.root.natFor(port)
	}
	d.portsAccess.Lock()
	defer d.portsAccess.Unlock()
	returnPath, loaded := d.ports[port]
	if loaded {
		return returnPath.nat
	}
	returnPath = &portReturn{
		dispatcher: d,
		nat:        acquirePortNAT(port),
		fragments:  fragmentTable{entries: make(map[fragmentKey]*fragmentEntry)},
	}
	err := port.AttachReturn(returnPath)
	if err != nil {
		releasePortNAT(returnPath.nat)
		d.logger.Trace(E.Cause(err, "attach return path"))
		return nil
	}
	d.ports[port] = returnPath
	return returnPath.nat
}

type relayOutput interface {
	relayHeadroom() int
	relayReserve(count int, size int) ([][]byte, []int)
	relayPacket(packet []byte)
	relaySegment(segment []byte)
	relayTooBig(packet *forwardPacket, mtu uint32)
}

type stagePortOutput struct {
	stage    *ForwardDispatcher
	flow     *forwardFlow
	borrowed bool
}

func (o *stagePortOutput) relayHeadroom() int {
	return 0
}

func (o *stagePortOutput) relayReserve(count int, size int) ([][]byte, []int) {
	return o.stage.reserveSegments(count, size)
}

func (o *stagePortOutput) relayPacket(packet []byte) {
	if o.borrowed {
		staged, _ := o.stage.reserveSegments(1, len(packet))
		copy(staged[0], packet)
		packet = staged[0]
	}
	o.stage.stagePort(o.flow, packet)
}

func (o *stagePortOutput) relaySegment(segment []byte) {
	o.stage.stagePort(o.flow, segment)
}

func (o *stagePortOutput) relayTooBig(packet *forwardPacket, mtu uint32) {
	o.stage.stageTooBig(packet, mtu)
}

func (s *ForwardDispatcher) stageTooBig(packet *forwardPacket, mtu uint32) {
	reply, ok := BuildICMPError(packet.network, ICMPErrorPacketTooBig, netip.Addr{}, mtu, s.writeback.ReturnHeadroom())
	if ok {
		s.writebackBatch = append(s.writebackBatch, reply)
	}
}

func (d *ForwardDispatcher) forwardToPort(flow *forwardFlow, packet *forwardPacket, raw []byte) {
	if !flow.IsActive() {
		return
	}
	d.portOutput.flow = flow
	d.portOutput.borrowed = packet.frameMeta != nil
	relayFlow(&d.portOutput, d.logger, flow, &flow.forwardRule, packet, raw, packet.frameMeta, false)
}

func relayFlow(output relayOutput, log logger.Logger, flow *forwardFlow, rule *rewriteRule, packet *forwardPacket, raw []byte, meta *ForwardFrameMeta, reverse bool) {
	effectiveMTU := flow.effectiveMTU
	if meta != nil {
		meta.completeChecksum(raw)
		if meta.gsoSize != 0 && packet.protocol == uint8(header.TCPProtocolNumber) {
			headerLength := len(raw) - len(packet.transport) + int(header.TCP(packet.transport).DataOffset())
			offloadMTU := uint32(headerLength) + uint32(meta.gsoSize)
			if effectiveMTU == 0 || offloadMTU < effectiveMTU {
				effectiveMTU = offloadMTU
			}
		}
	}
	if effectiveMTU != 0 && uint32(len(raw)) > effectiveMTU {
		if packet.protocol == uint8(header.TCPProtocolNumber) {
			headerLength, segmentSize, segmentable := tcpSegmentSize(packet, raw, effectiveMTU)
			if segmentable {
				countRelay(flow, len(raw), reverse)
				rewritePacket(packet, rule, flow.effectiveMTU)
				err := segmentTCP(output, packet, raw, headerLength, segmentSize)
				if err != nil {
					log.Trace(E.Cause(err, "segment packet"))
				}
				return
			}
		} else if packet.ipVersion == 4 && header.IPv4(packet.network).Flags()&header.IPv4FlagDontFragment == 0 {
			countRelay(flow, len(raw), reverse)
			rewritePacket(packet, rule, flow.effectiveMTU)
			fragments, ok := fragmentIPv4Packet(header.IPv4(packet.network), flow.effectiveMTU, output.relayHeadroom())
			if ok {
				for _, fragment := range fragments {
					output.relaySegment(fragment)
				}
			}
			return
		}
		output.relayTooBig(packet, flow.effectiveMTU)
		return
	}
	countRelay(flow, len(raw), reverse)
	rewritePacket(packet, rule, flow.effectiveMTU)
	output.relayPacket(raw)
}

func countRelay(flow *forwardFlow, n int, reverse bool) {
	if flow.tracker == nil {
		return
	}
	if reverse {
		flow.tracker.CountReverse(n)
	} else {
		flow.tracker.CountForward(n)
	}
}

func rewritePacket(packet *forwardPacket, rule *rewriteRule, effectiveMTU uint32) {
	if rule == nil {
		return
	}
	if packet.fragment {
		if packet.hasFlow {
			applyRewrite(packet, rule)
		} else {
			applyRewriteAddresses(packet, rule)
		}
		return
	}
	if packet.isTCPSyn() {
		applyRewriteRaw(packet, rule)
		clampTCPMSS(packet, effectiveMTU)
		recomputeChecksums(packet)
	} else {
		applyRewrite(packet, rule)
	}
}

type stagedPort struct {
	nat        *portNAT
	packets    [][]byte
	udpPackets []UDPFlowPacket
}

func (d *ForwardDispatcher) stagePort(flow *forwardFlow, packet []byte) {
	index := slices.IndexFunc(d.stagedPorts, func(s stagedPort) bool { return s.nat == flow.nat })
	if index < 0 {
		d.stagedPorts = append(d.stagedPorts, stagedPort{nat: flow.nat})
		index = len(d.stagedPorts) - 1
	}
	staged := &d.stagedPorts[index]
	if flow.udpMapping != nil {
		staged.udpPackets = append(staged.udpPackets, UDPFlowPacket{Packet: packet, Flow: flow})
	} else {
		staged.packets = append(staged.packets, packet)
	}
}

func (d *ForwardDispatcher) flushPort(staged *stagedPort) {
	if len(staged.packets) > 0 {
		if err := staged.nat.port.WritePackets(staged.packets); err != nil {
			d.logger.Trace(E.Cause(err, "forward packets"))
		}
		clear(staged.packets)
		staged.packets = staged.packets[:0]
	}
	if len(staged.udpPackets) > 0 {
		if err := staged.nat.udpPort.WriteUDPFlowPackets(staged.udpPackets); err != nil {
			d.logger.Trace(E.Cause(err, "forward UDP packets"))
		}
		clear(staged.udpPackets)
		staged.udpPackets = staged.udpPackets[:0]
	}
}

func (d *ForwardDispatcher) stageReject(packet *forwardPacket) {
	reply, ok := buildReject(packet, d.writeback.ReturnHeadroom())
	if ok {
		d.writebackBatch = append(d.writebackBatch, reply)
	}
}

func (d *ForwardDispatcher) ResetNetwork() {
	if d != nil {
		d.root.resetStages()
	}
}

func (d *ForwardDispatcher) resetStages() {
	d.stagesAccess.Lock()
	stages := append([]*ForwardStage(nil), d.stages...)
	d.stagesAccess.Unlock()
	d.resetLocal()
	for _, stage := range stages {
		if stage.dispatcher != d {
			stage.dispatcher.resetLocal()
		}
	}
}

func (d *ForwardDispatcher) resetLocal() {
	d.access.Lock()
	defer d.access.Unlock()
	d.cancelPendingFlows()
	d.fragments.reset()
	for key, entry := range d.table {
		d.removeEntry(key, entry, FlowCloseReset)
	}
	d.discardStagedPackets()
}

func (d *ForwardDispatcher) Flush() {
	if d == nil || d.returnPath.closed.Load() {
		return
	}
	d.access.Lock()
	if d.returnPath.closed.Load() {
		d.access.Unlock()
		return
	}
	packets := d.flushPackets()
	d.access.Unlock()
	d.writeBackPackets(packets)
}

// Caller holds access. Port batches borrow the caller's TUN storage, so they
// must finish copying before unlocking. Synthesized replies own their buffers
// and can be written after releasing the dispatcher lock.
func (d *ForwardDispatcher) flushPackets() [][]byte {
	for index := range d.stagedPorts {
		d.flushPort(&d.stagedPorts[index])
	}
	if retain := max(d.segmentUsed, segmentRetainCount); len(d.segmentBuffers) > retain {
		clear(d.segmentBuffers[retain:])
		d.segmentBuffers = d.segmentBuffers[:retain]
		d.segmentSizes = d.segmentSizes[:retain]
	}
	d.segmentUsed = 0
	packets := d.writebackBatch
	d.writebackBatch = nil
	d.maybeSweep(d.now())
	return packets
}

func (d *ForwardDispatcher) writeBackPackets(packets [][]byte) {
	if len(packets) > 0 && !d.returnPath.closed.Load() {
		err := d.writeback.WriteReturnPackets(packets)
		if err != nil {
			d.logger.Trace(E.Cause(err, "write back packets"))
		}
	}
}

func (d *ForwardDispatcher) discardStagedPackets() {
	for i := range d.stagedPorts {
		staged := &d.stagedPorts[i]
		clear(staged.packets)
		staged.packets = staged.packets[:0]
		clear(staged.udpPackets)
		staged.udpPackets = staged.udpPackets[:0]
	}
	clear(d.writebackBatch)
	d.writebackBatch = nil
	d.segmentUsed = 0
}

func (d *ForwardDispatcher) entryExpired(entry *flowEntry, now int64) bool {
	if entry.flow != nil && (entry.flow.aborted.Load() || routeExpired(entry.flow.routeContexts)) {
		return true
	}
	if now <= entry.deadline {
		return false
	}
	if entry.action == ActionFlow {
		lastReverse := entry.flow.lastReverse.Load()
		reverseDeadline := lastReverse + int64(entry.idle)
		if lastReverse != 0 && now <= reverseDeadline {
			entry.deadline = reverseDeadline
			return false
		}
	}
	return true
}

// gVisor's ordinary forwarders see packets after this dispatcher. Reuse an
// installed stack decision instead of doing first-packet DNS a second time,
// especially inside the UDP NAT cache's creation callback.
func (d *ForwardDispatcher) judgeFlowForStack(handler Handler, protocol uint8, source, destination netip.AddrPort, firstPacket []byte) FlowVerdict {
	if d != nil {
		d.access.Lock()
		if d.returnPath.closed.Load() {
			d.access.Unlock()
			return FlowVerdict{Action: ActionDrop}
		}
		entry := d.table[flowKey{protocol: protocol, source: source, destination: destination}]
		if entry != nil && entry.action != ActionFlow && !d.entryExpired(entry, d.now()) {
			verdict := entry.verdict
			if entry.action != ActionAccept {
				verdict = FlowVerdict{Action: entry.action}
			}
			d.access.Unlock()
			return verdict
		}
		d.access.Unlock()
	}
	return handler.JudgeFlow(protocol, source, destination, firstPacket)
}

func (d *ForwardDispatcher) tombstoneEntry(entry *flowEntry, now int64) {
	entry.action = ActionDrop
	entry.idle = flowTombstoneTimeout
	entry.deadline = now + int64(entry.idle)
}

func (d *ForwardDispatcher) removeEntry(key flowKey, entry *flowEntry, reason FlowCloseReason) {
	delete(d.table, key)
	if entry.flow != nil {
		if reason == FlowCloseTimeout && entry.flow.finForward.Load() && entry.flow.finReverse.Load() {
			reason = FlowCloseFinished
		}
		entry.flow.close(reason)
		entry.flow.nat.release(entry.flow)
	}
}

func (d *ForwardDispatcher) insertEntry(key flowKey, entry *flowEntry, now int64) {
	if len(d.table) >= d.tableCapacity() {
		d.evictEntries(now)
	}
	d.table[key] = entry
}

func (d *ForwardDispatcher) evictEntries(now int64) {
	var (
		freed     int
		visited   int
		oldestKey flowKey
		oldest    *flowEntry
	)
	for key, entry := range d.table {
		if d.entryExpired(entry, now) {
			d.removeEntry(key, entry, FlowCloseTimeout)
			freed++
		} else if oldest == nil || entry.deadline < oldest.deadline {
			oldestKey = key
			oldest = entry
		}
		visited++
		if visited >= flowSweepLimit {
			break
		}
	}
	if freed == 0 && oldest != nil {
		d.removeEntry(oldestKey, oldest, FlowCloseReset)
	}
}

func (d *ForwardDispatcher) maybeSweep(now int64) {
	if now-d.lastSweep < int64(flowSweepInterval) {
		return
	}
	d.lastSweep = now
	visited := 0
	for key, entry := range d.table {
		if d.entryExpired(entry, now) {
			d.removeEntry(key, entry, FlowCloseTimeout)
		} else if entry.action == ActionFlow && entry.flow.closed.Load() {
			d.tombstoneEntry(entry, now)
		}
		visited++
		if visited >= flowSweepLimit {
			break
		}
	}
}

func isICMPProtocol(protocol uint8) bool {
	return protocol == uint8(header.ICMPv4ProtocolNumber) || protocol == uint8(header.ICMPv6ProtocolNumber)
}

type forwardReturn struct {
	dispatcher *ForwardDispatcher
	closed     atomic.Bool
}

type portReturn struct {
	dispatcher     *ForwardDispatcher
	nat            *portNAT
	fragmentAccess sync.Mutex
	fragments      fragmentTable
}

func (r *portReturn) ReturnHeadroom() int {
	return r.dispatcher.writeback.ReturnHeadroom()
}

type returnDecision uint8

const (
	returnPass returnDecision = iota
	returnWrite
	returnDrop
)

type returnBatch struct {
	writeback ForwardWriteback
	packets   [][]byte
}

type returnOutput struct {
	returnPath *portReturn
	ingress    ForwardWriteback
	headroom   int
	raw        []byte
	writeback  ForwardWriteback
	batches    []returnBatch
}

func (o *returnOutput) relayHeadroom() int {
	return o.headroom
}

func (o *returnOutput) relayReserve(count int, size int) ([][]byte, []int) {
	buffers := make([][]byte, count)
	for index := range buffers {
		buffers[index] = make([]byte, size)
	}
	return buffers, make([]int, count)
}

func (o *returnOutput) relayPacket(packet []byte) {
	raw := o.raw
	if raw == nil {
		raw = make([]byte, o.headroom+len(packet))
		copy(raw[o.headroom:], packet)
	}
	o.relaySegment(raw)
}

func (o *returnOutput) relaySegment(segment []byte) {
	index := slices.IndexFunc(o.batches, func(batch returnBatch) bool { return batch.writeback == o.writeback })
	if index < 0 {
		o.batches = append(o.batches, returnBatch{writeback: o.writeback})
		index = len(o.batches) - 1
	}
	o.batches[index].packets = append(o.batches[index].packets, segment)
}

func (o *returnOutput) relayTooBig(packet *forwardPacket, mtu uint32) {
	headroom := 0
	if o.ingress != nil {
		headroom = o.ingress.ReturnHeadroom()
	}
	reply, ok := BuildICMPError(packet.network, ICMPErrorPacketTooBig, netip.Addr{}, mtu, headroom)
	if !ok {
		return
	}
	var err error
	if o.ingress == nil {
		err = o.returnPath.nat.port.WritePackets([][]byte{reply})
	} else {
		err = o.ingress.WriteReturnPackets([][]byte{reply})
	}
	if err != nil {
		o.returnPath.dispatcher.logger.Trace(E.Cause(err, "write packet too big"))
	}
}

func (o *returnOutput) flush() {
	for _, batch := range o.batches {
		err := batch.writeback.WriteReturnPackets(batch.packets)
		if err != nil {
			o.returnPath.dispatcher.logger.Trace(E.Cause(err, "write return packets"))
		}
	}
}

func (r *portReturn) ReturnPackets(packets [][]byte) [][]byte {
	if r.dispatcher.returnPath.closed.Load() {
		return packets
	}
	headroom := r.ReturnHeadroom()
	output := returnOutput{returnPath: r}
	now := r.dispatcher.now()
	unconsumed := packets[:0]
	for _, raw := range packets {
		if len(raw) < headroom+header.IPv4MinimumSize {
			unconsumed = append(unconsumed, raw)
			continue
		}
		parsed, ok := parseForwardPacket(raw[headroom:])
		if !ok {
			unconsumed = append(unconsumed, raw)
			continue
		}
		decision, flow, rule := r.classify(&parsed, now)
		switch decision {
		case returnWrite:
			output.writeback = flow.owner.writeback
			output.headroom = output.writeback.ReturnHeadroom()
			output.raw = nil
			if output.headroom == headroom {
				output.raw = raw
			}
			relayFlow(&output, r.dispatcher.logger, flow, rule, &parsed, raw[headroom:], nil, true)
		case returnDrop:
		default:
			unconsumed = append(unconsumed, raw)
		}
	}
	output.flush()
	return unconsumed
}

func (r *portReturn) classify(parsed *forwardPacket, now int64) (returnDecision, *forwardFlow, *rewriteRule) {
	if parsed.fragment {
		return r.classifyFragment(parsed, now)
	}
	if !parsed.hasFlow {
		if parsed.isICMPError() {
			flow := r.returnICMPError(parsed)
			if flow != nil {
				return returnWrite, flow, nil
			}
		}
		return returnPass, nil, nil
	}
	var scratch rewriteRule
	flow, rule := r.matchReverse(parsed, &scratch)
	if flow == nil {
		return returnPass, nil, nil
	}
	if !flow.IsActive() {
		return returnDrop, nil, nil
	}
	flow.observeReverse(parsed, now)
	return returnWrite, flow, rule
}

var errNoDispatcher = E.New("stack has no flow dispatcher")

func (d *ForwardDispatcher) attachReturn(returnPath Return) error {
	if d == nil {
		return errNoDispatcher
	}
	portReturnPath, isPortReturn := returnPath.(*portReturn)
	if !isPortReturn {
		return E.New("unsupported return path")
	}
	d.returnsAccess.Lock()
	defer d.returnsAccess.Unlock()
	current := *d.returns.Load()
	if slices.Contains(current, portReturnPath) {
		return nil
	}
	updated := append(slices.Clone(current), portReturnPath)
	d.returns.Store(&updated)
	return nil
}

func (d *ForwardDispatcher) detachReturn(returnPath Return) {
	if d == nil {
		return
	}
	portReturnPath, isPortReturn := returnPath.(*portReturn)
	if !isPortReturn {
		return
	}
	d.returnsAccess.Lock()
	defer d.returnsAccess.Unlock()
	current := *d.returns.Load()
	index := slices.Index(current, portReturnPath)
	if index < 0 {
		return
	}
	updated := slices.Delete(slices.Clone(current), index, index+1)
	d.returns.Store(&updated)
}

func (s *ForwardStage) ReturnParsed(packet []byte, meta ForwardFrameMeta, parsed *forwardPacket) bool {
	if s == nil || s.dispatcher.returnPath.closed.Load() {
		return false
	}
	for _, returnPath := range *s.dispatcher.root.returns.Load() {
		decision, flow, rule := returnPath.classify(parsed, returnPath.dispatcher.now())
		switch decision {
		case returnWrite:
			writeback := flow.owner.writeback
			output := returnOutput{returnPath: returnPath, ingress: s.dispatcher.writeback, writeback: writeback, headroom: writeback.ReturnHeadroom()}
			if output.headroom == 0 {
				output.raw = packet
			}
			relayFlow(&output, s.dispatcher.logger, flow, rule, parsed, packet, &meta, true)
			output.flush()
			return true
		case returnDrop:
			return true
		}
	}
	return false
}

func (r *portReturn) matchReverse(parsed *forwardPacket, scratch *rewriteRule) (*forwardFlow, *rewriteRule) {
	key := parsed.flowKey()
	flow := r.nat.lookup(key)
	if flow != nil {
		if flow.owner.root != r.dispatcher {
			return nil, nil
		}
		return flow, &flow.reverseRule
	}
	if parsed.protocol != uint8(header.UDPProtocolNumber) {
		return nil, nil
	}
	if r.nat.udpPort != nil {
		flow, rule := r.nat.matchUDPFlow(parsed, nil)
		if flow == nil || flow.owner.root != r.dispatcher {
			return nil, nil
		}
		*scratch = rule
		return flow, scratch
	}
	mapping, anchor := r.nat.lookupMapping(key.destination.Addr(), key.destination.Port(), key.source.Addr())
	if mapping == nil || mapping.key.dispatcher != r.dispatcher {
		return nil, nil
	}
	return anchor, &mapping.reverseRule
}

func (r *portReturn) returnICMPError(parsed *forwardPacket) *forwardFlow {
	inner, ok := parsed.icmpErrorInner()
	if !ok {
		return nil
	}
	embedded, parsedInner := parseEmbedded(inner)
	if !parsedInner {
		return nil
	}
	flow := r.nat.lookup(embedded.flowKey().reversed())
	if flow == nil || flow.owner.root != r.dispatcher || !flow.IsActive() {
		return nil
	}
	rewriteEmbeddedSource(&embedded, addrToTCPIP(flow.clientAddress), flow.clientSelector, true)
	if flow.dnatAddress || flow.dnatPort {
		rewriteEmbeddedDestination(&embedded, addrToTCPIP(flow.clientDestinationAddress), flow.clientDestinationPort, flow.dnatPort)
	}
	sourceAddress, destinationAddress := parsed.addressSlices()
	copy(destinationAddress, flow.clientAddress.AsSlice())
	if parsed.source.Addr() == flow.serverAddress {
		copy(sourceAddress, flow.clientDestinationAddress.AsSlice())
	}
	recomputeChecksums(parsed)
	return flow
}

type heldPacket struct {
	packet []byte
	meta   ForwardFrameMeta
}

func (s *ForwardDispatcher) dispatchFragment(packet []byte, parsed *forwardPacket) bool {
	now := s.now()
	s.access.Lock()
	defer s.access.Unlock()
	entry := s.fragments.lookup(parsed.fragmentKey(), parsed.fragmentInfo, now)
	if entry == nil {
		return false
	}
	if entry.pending {
		return s.fragments.hold(entry, packet, parsed.frameMeta)
	}
	if entry.flow.IsActive() {
		s.forwardToPort(entry.flow, parsed, packet)
	}
	return true
}

func (s *ForwardDispatcher) resolveFragments(parsed *forwardPacket, key flowKey, handled bool, now int64) []heldPacket {
	var (
		flow *forwardFlow
		rule *rewriteRule
	)
	entry := s.table[key]
	if entry != nil && handled && entry.action == ActionFlow && entry.flow.IsActive() {
		flow = entry.flow
		rule = &flow.forwardRule
	}
	held := s.fragments.resolve(parsed.fragmentKey(), parsed.fragmentInfo, flow, rule, now)
	if flow == nil {
		if handled {
			return nil
		}
		return held
	}
	for index := range held {
		fragment := &held[index]
		fragmentParsed, _ := parseForwardPacket(fragment.packet)
		fragmentParsed.frameMeta = &fragment.meta
		s.forwardToPort(flow, &fragmentParsed, fragment.packet)
	}
	return nil
}
