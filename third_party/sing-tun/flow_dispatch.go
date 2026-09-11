package tun

import (
	"context"
	"encoding/binary"
	"maps"
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
	needsChecksum  bool
	checksumStart  uint16
	checksumOffset uint16
	gsoType        uint8
	gsoSize        uint16
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
	binary.BigEndian.PutUint16(raw[checksumAt:], ^checksum.Checksum(raw[m.checksumStart:], initial))
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
	epoch        time.Time
	handler      Handler
	writeback    ForwardWriteback
	logger       logger.Logger
	udpTimeout   time.Duration
	icmpTimeout  time.Duration
	access       sync.Mutex
	root         *ForwardDispatcher
	stagesAccess sync.Mutex
	stages       []*ForwardStage
	portsAccess  sync.Mutex

	table     map[flowKey]*flowEntry
	lastSweep int64
	ports     map[Port]*portNAT
	natList   atomic.Pointer[[]*portNAT]
	revNAT    atomic.Pointer[map[netip.Addr]*portNAT]

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
	dispatcher := &ForwardDispatcher{
		epoch:       time.Now(),
		handler:     handler,
		writeback:   writeback,
		logger:      logger,
		udpTimeout:  udpTimeout,
		icmpTimeout: icmpTimeout,
		table:       make(map[flowKey]*flowEntry),
		ports:       make(map[Port]*portNAT),
	}
	if dispatcher.udpTimeout <= 0 {
		dispatcher.udpTimeout = defaultUDPTimeout
	}
	if dispatcher.icmpTimeout <= 0 {
		dispatcher.icmpTimeout = defaultICMPTimeout
	}
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
	ports := make([]Port, 0, len(root.ports))
	for port := range root.ports {
		ports = append(ports, port)
	}
	root.portsAccess.Unlock()
	for _, port := range ports {
		port.DetachReturn(root.returnPath)
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
	if parsed.fragment || !parsed.hasFlow {
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
			d.enqueuePendingPacket(pending, packet)
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
			if packet.tcpFlags&header.TCPFlagRst != 0 {
				d.removeEntry(key, entry, FlowCloseReset)
				return false
			}
			if packet.tcpFlags&header.TCPFlagSyn == 0 {
				entry.idle = tcpEstablishedTimeout
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
	if verdict.Action == ActionHijackDNS && packet.protocol == uint8(header.UDPProtocolNumber) {
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
	return d.installVerdict(key, packet, raw, verdict)
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
	selector, reverseKey, allocated := nat.allocateSelector(packet.protocol, portAddress, serverAddress, serverPort, packet.source, packet.destination)
	if !allocated {
		return nil, createFlowExhausted
	}
	var udpTimeout time.Duration
	if packet.protocol == uint8(header.UDPProtocolNumber) {
		udpTimeout = verdict.UDPTimeout
	}
	flow := &forwardFlow{
		nat:                      nat,
		owner:                    d,
		reverseKey:               reverseKey,
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
	flow.forwardRule = rewriteRule{
		sourceAddress:     addrToTCPIP(portAddress),
		sourcePort:        selector,
		rewriteSourcePort: true,
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
	nat.insert(reverseKey, flow)
	return flow, createFlowOK
}

func (d *ForwardDispatcher) natFor(port Port) *portNAT {
	if d.root != d {
		return d.root.natFor(port)
	}
	d.portsAccess.Lock()
	defer d.portsAccess.Unlock()
	nat, loaded := d.ports[port]
	if loaded {
		return nat
	}
	err := port.AttachReturn(d.returnPath)
	if err != nil {
		d.logger.Trace(E.Cause(err, "attach return path"))
		return nil
	}
	nat = newPortNAT(port, d.returnPath)
	d.ports[port] = nat
	var natList []*portNAT
	current := d.natList.Load()
	if current != nil {
		natList = append(natList, *current...)
	}
	natList = append(natList, nat)
	d.natList.Store(&natList)
	revMap := make(map[netip.Addr]*portNAT)
	if currentRev := d.revNAT.Load(); currentRev != nil {
		maps.Copy(revMap, *currentRev)
	}
	v4Address, v6Address := port.PortAddresses()
	if v4Address.IsValid() {
		revMap[v4Address] = nat
	}
	if v6Address.IsValid() {
		revMap[v6Address] = nat
	}
	d.revNAT.Store(&revMap)
	return nat
}

func (d *ForwardDispatcher) forwardToPort(flow *forwardFlow, packet *forwardPacket, raw []byte) {
	if routeExpired(flow.routeContexts) {
		return
	}
	meta := packet.frameMeta
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
			if flow.tracker != nil {
				flow.tracker.CountForward(len(raw))
			}
			d.rewriteForward(flow, packet)
			d.resegmentTCP(flow, packet, raw, effectiveMTU)
			return
		}
		if packet.ipVersion == 4 {
			ipHdr := header.IPv4(packet.network)
			if ipHdr.Flags()&header.IPv4FlagDontFragment == 0 {
				if flow.tracker != nil {
					flow.tracker.CountForward(len(raw))
				}
				d.rewriteForward(flow, packet)
				fragments, ok := fragmentIPv4Packet(ipHdr, flow.effectiveMTU)
				if ok {
					for _, fragment := range fragments {
						d.stagePort(flow, fragment)
					}
				}
				return
			}
			reply, ok := buildFragmentationNeeded(ipHdr, flow.effectiveMTU, d.writeback.ReturnHeadroom())
			if ok {
				d.writebackBatch = append(d.writebackBatch, reply)
			}
			return
		}
		reply, ok := buildPacketTooBig(header.IPv6(packet.network), flow.effectiveMTU, d.writeback.ReturnHeadroom())
		if ok {
			d.writebackBatch = append(d.writebackBatch, reply)
		}
		return
	}
	if flow.tracker != nil {
		flow.tracker.CountForward(len(raw))
	}
	d.rewriteForward(flow, packet)
	if meta != nil {
		raw = d.copyForStage(raw)
	}
	d.stagePort(flow, raw)
}

func (d *ForwardDispatcher) rewriteForward(flow *forwardFlow, packet *forwardPacket) {
	if packet.isTCPSyn() {
		applyRewriteRaw(packet, &flow.forwardRule)
		clampTCPMSS(packet, flow.effectiveMTU)
		recomputeChecksums(packet)
	} else {
		applyRewrite(packet, &flow.forwardRule)
	}
}

func (d *ForwardDispatcher) copyForStage(raw []byte) []byte {
	staged, _ := d.reserveSegments(1, len(raw))
	copy(staged[0], raw)
	return staged[0]
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
	if entry.flow != nil && routeExpired(entry.flow.routeContexts) {
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
			action := entry.action
			d.access.Unlock()
			return FlowVerdict{Action: action}
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
		entry.flow.nat.delete(entry.flow.reverseKey)
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
		if entry.action == ActionFlow && entry.flow.closed.Load() {
			d.tombstoneEntry(entry, now)
		} else if d.entryExpired(entry, now) {
			d.removeEntry(key, entry, FlowCloseTimeout)
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

var _ Return = (*forwardReturn)(nil)

type forwardReturn struct {
	dispatcher *ForwardDispatcher
	closed     atomic.Bool
}

func (r *forwardReturn) ReturnHeadroom() int {
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

func (r *forwardReturn) ReturnPackets(packets [][]byte) [][]byte {
	if r.closed.Load() {
		return packets
	}
	natListPtr := r.dispatcher.natList.Load()
	if natListPtr == nil {
		return packets
	}
	natList := *natListPtr
	var revMap map[netip.Addr]*portNAT
	if revPtr := r.dispatcher.revNAT.Load(); revPtr != nil {
		revMap = *revPtr
	}
	headroom := r.dispatcher.writeback.ReturnHeadroom()
	now := r.dispatcher.now()
	if len(packets) == 1 {
		decision, writeback := r.classifyReturn(packets[0], natList, revMap, headroom, now)
		switch decision {
		case returnWrite:
			if err := writeback.WriteReturnPackets(packets[:1]); err != nil {
				r.dispatcher.logger.Trace(E.Cause(err, "write return packets"))
			}
			return packets[:0]
		case returnDrop:
			return packets[:0]
		default:
			return packets
		}
	}
	unconsumed := packets[:0]
	var batches []returnBatch
	for _, raw := range packets {
		decision, writeback := r.classifyReturn(raw, natList, revMap, headroom, now)
		switch decision {
		case returnWrite:
			index := slices.IndexFunc(batches, func(batch returnBatch) bool { return batch.writeback == writeback })
			if index < 0 {
				batches = append(batches, returnBatch{writeback: writeback})
				index = len(batches) - 1
			}
			batches[index].packets = append(batches[index].packets, raw)
		case returnDrop:
		default:
			unconsumed = append(unconsumed, raw)
		}
	}
	for _, batch := range batches {
		err := batch.writeback.WriteReturnPackets(batch.packets)
		if err != nil {
			r.dispatcher.logger.Trace(E.Cause(err, "write return packets"))
		}
	}
	return unconsumed
}

func (r *forwardReturn) classifyReturn(raw []byte, natList []*portNAT, revMap map[netip.Addr]*portNAT, headroom int, now int64) (returnDecision, ForwardWriteback) {
	if len(raw) < headroom+header.IPv4MinimumSize {
		return returnPass, nil
	}
	parsed, ok := parseForwardPacket(raw[headroom:])
	if !ok || parsed.fragment {
		return returnPass, nil
	}
	if !parsed.hasFlow {
		if parsed.isICMPError() {
			flow := returnICMPError(natList, revMap, &parsed)
			if flow != nil {
				return returnWrite, flow.owner.writeback
			}
		}
		return returnPass, nil
	}
	flow := findReverseFlow(natList, revMap, parsed.flowKey())
	if flow == nil {
		if nat := revMap[parsed.destination.Addr()]; nat != nil {
			if owner := nat.returnUDPFlow(&parsed, len(raw)-headroom, now, nil); owner != nil {
				return returnWrite, owner.owner.writeback
			}
		}
		return returnPass, nil
	}
	if !flow.IsActive() {
		return returnDrop, nil
	}
	if flow.tracker != nil {
		flow.tracker.CountReverse(len(raw) - headroom)
	}
	flow.observeReverse(&parsed, now)
	if parsed.isTCPSyn() {
		applyRewriteRaw(&parsed, &flow.reverseRule)
		clampTCPMSS(&parsed, flow.effectiveMTU)
		recomputeChecksums(&parsed)
	} else {
		applyRewrite(&parsed, &flow.reverseRule)
	}
	return returnWrite, flow.owner.writeback
}

func findReverseFlow(natList []*portNAT, revMap map[netip.Addr]*portNAT, key flowKey) *forwardFlow {
	if nat, ok := revMap[key.destination.Addr()]; ok {
		if flow := nat.lookup(key); flow != nil {
			return flow
		}
	}
	for _, nat := range natList {
		if flow := nat.lookup(key); flow != nil {
			return flow
		}
	}
	return nil
}

func returnICMPError(natList []*portNAT, revMap map[netip.Addr]*portNAT, parsed *forwardPacket) *forwardFlow {
	inner, ok := parsed.icmpErrorInner()
	if !ok {
		return nil
	}
	embedded, parsedInner := parseEmbedded(inner)
	if !parsedInner {
		return nil
	}
	flow := findReverseFlow(natList, revMap, embedded.flowKey().reversed())
	if flow == nil || !flow.IsActive() {
		return nil
	}
	rewriteEmbeddedSource(&embedded, addrToTCPIP(flow.clientAddress), flow.clientSelector, true)
	if flow.dnatAddress || flow.dnatPort {
		rewriteEmbeddedDestination(&embedded, addrToTCPIP(flow.clientDestinationAddress), flow.clientDestinationPort, flow.dnatPort)
	}
	networkHeader := parsed.networkHeader()
	networkHeader.SetDestinationAddr(flow.clientAddress)
	if networkHeader.SourceAddr() == flow.serverAddress {
		networkHeader.SetSourceAddr(flow.clientDestinationAddress)
	}
	recomputeChecksums(parsed)
	return flow
}
