package tun

import (
	"context"
	"net/netip"

	"github.com/sagernet/sing-tun/gtcpip/header"
)

type udpMapping struct {
	nat    *portNAT
	source netip.AddrPort
	ctx    context.Context
	cancel context.CancelFunc
	client netip.AddrPort
	peers  map[netip.Addr]*udpPeer
	flows  int
}

type udpPeer struct {
	destination netip.Addr
	flows       map[*forwardFlow]struct{}
}

func (p *udpPeer) activeFlow() *forwardFlow {
	for f := range p.flows {
		if !f.closed.Load() && !routeExpired(f.routeContexts) {
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
	for _, peer := range m.peers {
		if peer.activeFlow() != nil {
			return true
		}
	}
	return false
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
	if flow := m.nat.lookup(packet.flowKey()); flow != nil {
		if flow.udpMapping != m || flow.closed.Load() || routeExpired(flow.routeContexts) {
			return false
		}
		if flow.tracker != nil {
			flow.tracker.CountReverse(size)
		}
		flow.observeReverse(&packet, now)
		applyRewrite(&packet, &flow.reverseRule)
	} else if !m.nat.returnUDP(&packet, size, now, m) {
		return false
	}
	d.writeBackPackets([][]byte{raw})
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
	mapping.flows++
	f.udpMapping = mapping
}

func (n *portNAT) deleteUDPMapping(key flowKey, f *forwardFlow) {
	if n.udpMappings == nil || key.protocol != uint8(header.UDPProtocolNumber) {
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
	mapping.flows--
	// Retain an inactive peer's alias while another flow uses this socket.
	// Otherwise late replies become "new peers", or a different Fake-IP can
	// silently inherit the old association. Peer history is bounded by the
	// flow table capacity; allocation starts another socket at that limit.
	if mapping.flows == 0 {
		delete(n.udpMappings, key.destination)
		delete(n.udpClients[mapping.client], key.destination)
		if len(n.udpClients[mapping.client]) == 0 {
			delete(n.udpClients, mapping.client)
		}
		mapping.cancel()
	}
}

func (n *portNAT) returnUDP(packet *forwardPacket, size int, now int64, expected *udpMapping) bool {
	if n.udpMappings == nil || packet.protocol != uint8(header.UDPProtocolNumber) {
		return false
	}
	n.udpAccess.RLock()
	var owner *forwardFlow
	if mapping := n.udpMappings[packet.destination]; mapping != nil && (expected == nil || mapping == expected) {
		if peer := mapping.peers[packet.source.Addr()]; peer != nil {
			owner = peer.activeFlow()
		} else {
			for _, peer := range mapping.peers {
				if owner = peer.activeFlow(); owner != nil {
					break
				}
			}
		}
	}
	n.udpAccess.RUnlock()
	if owner == nil {
		return false
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
	return true
}
