package tun

import (
	"net/netip"

	"github.com/sagernet/sing-tun/gtcpip/header"
)

type udpMapping struct {
	client netip.AddrPort
	peers  map[netip.Addr]*udpPeer
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
	return mapping.client == client && (peer == nil || peer.destination == destination)
}

func (n *portNAT) insertUDPMapping(key flowKey, f *forwardFlow) {
	if n.udpMappings == nil || key.protocol != uint8(header.UDPProtocolNumber) {
		return
	}
	n.udpAccess.Lock()
	defer n.udpAccess.Unlock()
	mapping := n.udpMappings[key.destination]
	if mapping == nil {
		mapping = &udpMapping{client: netip.AddrPortFrom(f.clientAddress, f.clientSelector), peers: make(map[netip.Addr]*udpPeer)}
		n.udpMappings[key.destination] = mapping
	}
	peer := mapping.peers[key.source.Addr()]
	if peer == nil {
		peer = &udpPeer{destination: f.clientDestinationAddress, flows: make(map[*forwardFlow]struct{})}
		mapping.peers[key.source.Addr()] = peer
	}
	peer.flows[f] = struct{}{}
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
	if len(peer.flows) == 0 {
		delete(mapping.peers, key.source.Addr())
	}
	if len(mapping.peers) == 0 {
		delete(n.udpMappings, key.destination)
	}
}

func (n *portNAT) returnUDP(packet *forwardPacket, size int, now int64) bool {
	if n.udpMappings == nil || packet.protocol != uint8(header.UDPProtocolNumber) {
		return false
	}
	n.udpAccess.RLock()
	var owner *forwardFlow
	if mapping := n.udpMappings[packet.destination]; mapping != nil {
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
