package tun

import (
	"net/netip"
	"runtime"
	"sync"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/contrab/maphash"
)

const (
	natSelectorMin = 49152
	natSelectorMax = 65535
)

type portNAT struct {
	port          Port
	hasher        maphash.Hasher[flowKey]
	shardMask     uint32
	shards        []natShard
	selectorStart uint16
	selectorCount uint16
	udpAccess     sync.RWMutex
	udpMappings   map[netip.AddrPort]*udpMapping

	counter uint32
	pending [][]byte
}

type natShard struct {
	access sync.RWMutex
	flows  map[flowKey]*forwardFlow
}

func newPortNAT(port Port) *portNAT {
	shardCount := 1
	for shardCount < runtime.GOMAXPROCS(0) {
		shardCount <<= 1
	}
	nat := &portNAT{
		port:      port,
		hasher:    maphash.NewHasher[flowKey](),
		shardMask: uint32(shardCount - 1),
		shards:    make([]natShard, shardCount),
	}
	if rangedPort, isRanged := port.(PortWithSelectorRange); isRanged {
		nat.selectorStart, nat.selectorCount = rangedPort.PortSelectorRange()
	}
	if udpPort, ok := port.(PortWithUDPMapping); ok && udpPort.EndpointIndependentUDP() {
		nat.udpMappings = make(map[netip.AddrPort]*udpMapping)
	}
	for i := range nat.shards {
		nat.shards[i].flows = make(map[flowKey]*forwardFlow)
	}
	return nat
}

func (n *portNAT) shard(key flowKey) *natShard {
	return &n.shards[n.hasher.Hash32(key)&n.shardMask]
}

func (n *portNAT) lookup(key flowKey) *forwardFlow {
	shard := n.shard(key)
	shard.access.RLock()
	flow := shard.flows[key]
	shard.access.RUnlock()
	return flow
}

func (n *portNAT) insert(key flowKey, flow *forwardFlow) {
	shard := n.shard(key)
	shard.access.Lock()
	shard.flows[key] = flow
	shard.access.Unlock()
	n.insertUDPMapping(key, flow)
}

func (n *portNAT) delete(key flowKey) {
	shard := n.shard(key)
	shard.access.Lock()
	flow := shard.flows[key]
	delete(shard.flows, key)
	shard.access.Unlock()
	n.deleteUDPMapping(key, flow)
}

func (n *portNAT) reverseKeyFor(protocol uint8, portAddress, serverAddress netip.Addr, serverPort, selector uint16) flowKey {
	if protocol == uint8(header.ICMPv4ProtocolNumber) || protocol == uint8(header.ICMPv6ProtocolNumber) {
		return flowKey{
			protocol:    protocol,
			source:      netip.AddrPortFrom(serverAddress, selector),
			destination: netip.AddrPortFrom(portAddress, selector),
		}
	}
	return flowKey{
		protocol:    protocol,
		source:      netip.AddrPortFrom(serverAddress, serverPort),
		destination: netip.AddrPortFrom(portAddress, selector),
	}
}

func (n *portNAT) selectorRange(protocol uint8) (uint16, uint32) {
	if n.selectorCount == 0 ||
		protocol == uint8(header.ICMPv4ProtocolNumber) || protocol == uint8(header.ICMPv6ProtocolNumber) {
		return natSelectorMin, natSelectorMax - natSelectorMin + 1
	}
	return n.selectorStart, uint32(n.selectorCount)
}

func (n *portNAT) allocateSelector(protocol uint8, portAddress, serverAddress netip.Addr, serverPort uint16, client, destination netip.AddrPort) (uint16, flowKey, bool) {
	clientSelector := client.Port()
	rangeStart, rangeCount := n.selectorRange(protocol)
	if clientSelector != 0 &&
		clientSelector >= rangeStart && uint32(clientSelector-rangeStart) < rangeCount {
		key := n.reverseKeyFor(protocol, portAddress, serverAddress, serverPort, clientSelector)
		if n.lookup(key) == nil && n.canShareUDPMapping(key, client, destination.Addr()) {
			return clientSelector, key, true
		}
	}
	for range rangeCount {
		n.counter++
		candidate := rangeStart + uint16(n.counter%rangeCount)
		key := n.reverseKeyFor(protocol, portAddress, serverAddress, serverPort, candidate)
		if n.lookup(key) == nil && n.canShareUDPMapping(key, client, destination.Addr()) {
			return candidate, key, true
		}
	}
	return 0, flowKey{}, false
}
