package tun

import (
	"context"
	"net/netip"

	"github.com/sagernet/sing-tun/gtcpip/header"
)

type udpMapping struct {
	nat      *portNAT
	source   netip.AddrPort
	ctx      context.Context
	cancel   context.CancelFunc
	client   netip.AddrPort
	peers    map[netip.Addr]*udpPeer
	flowHead *forwardFlow
}

type udpPeer struct {
	destination netip.Addr
	flows       map[*forwardFlow]struct{}
}

func (p *udpPeer) activeFlow() *forwardFlow {
	for f := range p.flows {
		if f.IsActive() {
			return f
		}
	}
	return nil
}

func (f *forwardFlow) UDPMapping() UDPMapping { return f.udpMapping }

func (f *forwardFlow) IsActive() bool {
	return !f.closed.Load() && !routeExpired(f.routeContexts)
}

// Caller holds udpAccess. Search installed tuples, never retained peer history.
func (m *udpMapping) activeFlow() *forwardFlow {
	for f := m.flowHead; f != nil; f = f.udpNext {
		if f.IsActive() {
			return f
		}
	}
	return nil
}

func (m *udpMapping) Context() context.Context { return m.ctx }

func (m *udpMapping) IsActive() bool {
	if m.ctx.Err() != nil {
		return false
	}
	m.nat.udpAccess.RLock()
	defer m.nat.udpAccess.RUnlock()
	return m.activeFlow() != nil
}

func (r *forwardReturn) UDPMapping(source netip.AddrPort) UDPMapping {
	if r.closed.Load() {
		return nil
	}
	if rev := r.dispatcher.revNAT.Load(); rev != nil {
		if nat := (*rev)[source.Addr()]; nat != nil {
			nat.udpAccess.RLock()
			mapping := nat.udpMappings[source]
			nat.udpAccess.RUnlock()
			if mapping != nil {
				return mapping
			}
		}
	}
	return nil
}

func (m *udpMapping) ReturnPacket(raw []byte) bool {
	d := m.nat.returnPath.dispatcher
	headroom := d.writeback.ReturnHeadroom()
	if m.ctx.Err() != nil || d.returnPath.closed.Load() || len(raw) < headroom {
		return false
	}
	packet, ok := parseForwardPacket(raw[headroom:])
	if !ok || packet.fragment || packet.protocol != uint8(header.UDPProtocolNumber) || packet.destination != m.source {
		return false
	}
	now, size := d.now(), len(raw)-headroom
	flow := m.nat.lookup(packet.flowKey())
	if flow != nil {
		if flow.udpMapping != m || !flow.IsActive() {
			return false
		}
		if flow.tracker != nil {
			flow.tracker.CountReverse(size)
		}
		flow.observeReverse(&packet, now)
		applyRewrite(&packet, &flow.reverseRule)
	} else {
		flow = m.nat.returnUDPFlow(&packet, size, now, m)
		if flow == nil {
			return false
		}
	}
	flow.owner.writeBackPackets([][]byte{raw})
	return true
}

// Look up this application's existing associations before considering a new
// selector. Prefer an already known peer/alias over another compatible socket.
func (n *portNAT) findUDPMapping(client netip.AddrPort, server, destination netip.Addr, serverPort uint16) (netip.AddrPort, bool) {
	n.udpAccess.RLock()
	defer n.udpAccess.RUnlock()
	var compatible netip.AddrPort
	for source, mapping := range n.udpClients[client] {
		key := n.reverseKeyFor(uint8(header.UDPProtocolNumber), source.Addr(), server, serverPort, source.Port())
		if n.lookup(key) != nil {
			continue
		}
		if peer := mapping.peers[server]; peer != nil {
			if peer.destination == destination {
				return source, true
			}
		} else if len(mapping.peers) < flowTableCapacity {
			compatible = source
		}
	}
	return compatible, compatible.IsValid()
}

// The reverse tuple remains the fast path. This index is only used when a
// socket-style port receives a reply from an endpoint the client has not sent
// to. Each internal address/selector belongs to one original application
// endpoint; aliases of the same real IP must also agree on the reverse address.
func (n *portNAT) canShareUDPMapping(key flowKey, client netip.AddrPort, destination netip.Addr) bool {
	if n.udpMappings == nil || key.protocol != uint8(header.UDPProtocolNumber) {
		return true
	}
	n.udpAccess.RLock()
	defer n.udpAccess.RUnlock()
	mapping := n.udpMappings[key.destination]
	if mapping == nil {
		return true
	}
	peer := mapping.peers[key.source.Addr()]
	return mapping.client == client && ((peer == nil && len(mapping.peers) < flowTableCapacity) || (peer != nil && peer.destination == destination))
}

func (n *portNAT) insertUDPMapping(key flowKey, f *forwardFlow) {
	if n.udpMappings == nil || key.protocol != uint8(header.UDPProtocolNumber) {
		return
	}
	n.udpAccess.Lock()
	defer n.udpAccess.Unlock()
	mapping := n.udpMappings[key.destination]
	if mapping == nil {
		ctx, cancel := context.WithCancel(context.Background())
		mapping = &udpMapping{nat: n, source: key.destination, ctx: ctx, cancel: cancel, client: netip.AddrPortFrom(f.clientAddress, f.clientSelector), peers: make(map[netip.Addr]*udpPeer)}
		n.udpMappings[key.destination] = mapping
		if n.udpClients[mapping.client] == nil {
			n.udpClients[mapping.client] = make(map[netip.AddrPort]*udpMapping)
		}
		n.udpClients[mapping.client][key.destination] = mapping
	}
	peer := mapping.peers[key.source.Addr()]
	if peer == nil {
		peer = &udpPeer{destination: f.clientDestinationAddress, flows: make(map[*forwardFlow]struct{})}
		mapping.peers[key.source.Addr()] = peer
	}
	peer.flows[f] = struct{}{}
	f.udpNext = mapping.flowHead
	if f.udpNext != nil {
		f.udpNext.udpPrev = f
	}
	mapping.flowHead = f
	f.udpMapping = mapping
}

func (n *portNAT) deleteUDPMapping(key flowKey, f *forwardFlow) {
	if f == nil || n.udpMappings == nil || key.protocol != uint8(header.UDPProtocolNumber) {
		return
	}
	n.udpAccess.Lock()
	defer n.udpAccess.Unlock()
	mapping := n.udpMappings[key.destination]
	if mapping == nil {
		return
	}
	peer := mapping.peers[key.source.Addr()]
	if peer == nil {
		return
	}
	delete(peer.flows, f)
	if f.udpPrev != nil {
		f.udpPrev.udpNext = f.udpNext
	} else {
		mapping.flowHead = f.udpNext
	}
	if f.udpNext != nil {
		f.udpNext.udpPrev = f.udpPrev
	}
	f.udpPrev, f.udpNext = nil, nil
	// Retain an inactive peer's alias while another flow uses this socket.
	// Otherwise late replies become "new peers", or a different Fake-IP can
	// silently inherit the old association. Peer history is bounded by the
	// flow table capacity; allocation starts another socket at that limit.
	if mapping.flowHead == nil {
		delete(n.udpMappings, key.destination)
		delete(n.udpClients[mapping.client], key.destination)
		if len(n.udpClients[mapping.client]) == 0 {
			delete(n.udpClients, mapping.client)
		}
		mapping.cancel()
	}
}

func (n *portNAT) returnUDPFlow(packet *forwardPacket, size int, now int64, expected *udpMapping) *forwardFlow {
	if n.udpMappings == nil || packet.protocol != uint8(header.UDPProtocolNumber) {
		return nil
	}
	n.udpAccess.RLock()
	var owner *forwardFlow
	if mapping := n.udpMappings[packet.destination]; mapping != nil && (expected == nil || mapping == expected) {
		if peer := mapping.peers[packet.source.Addr()]; peer != nil {
			owner = peer.activeFlow()
		} else {
			owner = mapping.activeFlow()
		}
	}
	n.udpAccess.RUnlock()
	if owner == nil {
		return nil
	}
	// Keep the responder's actual port. Only a known real IP has a Fake-IP
	// alias; a new peer keeps its own source address.
	rule := rewriteRule{
		destinationAddress:     addrToTCPIP(owner.clientAddress),
		destinationPort:        owner.clientSelector,
		rewriteDestinationPort: true,
	}
	if owner.serverAddress == packet.source.Addr() && owner.dnatAddress {
		rule.sourceAddress = addrToTCPIP(owner.clientDestinationAddress)
	}
	if owner.tracker != nil {
		owner.tracker.CountReverse(size)
	}
	owner.observeReverse(packet, now)
	applyRewrite(packet, &rule)
	return owner
}
