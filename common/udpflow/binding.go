package udpflow

import (
	"context"
	"math"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

var nextPortID atomic.Uint64

// Each binding belongs to one inbound's selector allocator. All mutable
// binding state is protected by port.access; there is no worker per binding.
type portBinding struct {
	port          *Port
	inet4Address  netip.Addr
	inet6Address  netip.Addr
	returnPath    tun.Return
	mappingReturn tun.ReturnWithUDPMapping
	flows         map[netip.AddrPort]*flow
}

// ForInbound returns a stable port for this inbound. Creating a binding does
// not dial or start any goroutines. The default binding preserves the
// direct Port API for callers that already have a dedicated port.
func (p *Port) ForInbound(inbound string) (tun.Port, error) {
	p.access.Lock()
	defer p.access.Unlock()
	if p.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	if binding := p.bindings[inbound]; binding != nil {
		return binding, nil
	}
	binding, err := p.newBinding()
	if err != nil {
		return nil, err
	}
	p.bindings[inbound] = binding
	return binding, nil
}

func (p *Port) newBinding() (*portBinding, error) {
	id := nextPortID.Add(1)
	if id >= 1<<24 {
		return nil, E.New("UDP flow: internal port addresses exhausted")
	}
	return &portBinding{
		port: p,
		// These addresses only identify dispatcher mappings; they never
		// appear on the proxy connection or the TUN return packet.
		inet4Address: netip.AddrFrom4([4]byte{127, byte(id >> 16), byte(id >> 8), byte(id)}),
		inet6Address: netip.AddrFrom16([16]byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(id >> 16), byte(id >> 8), byte(id)}),
		flows:        make(map[netip.AddrPort]*flow),
	}, nil
}

func (b *portBinding) PortAddresses() (netip.Addr, netip.Addr) {
	return b.inet4Address, b.inet6Address
}

func (b *portBinding) PortMTU() uint32 {
	return b.port.mtu
}

func (b *portBinding) EndpointIndependentUDP() bool { return true }

func (b *portBinding) PortSelectorRange() (uint16, uint16) {
	// Preserve the application's source port when reply ownership and Fake-IP
	// aliases are unambiguous. sing-tun separates conflicting mappings.
	return 1, math.MaxUint16
}

func (b *portBinding) AttachReturn(returnPath tun.Return) error {
	p := b.port
	p.access.Lock()
	defer p.access.Unlock()
	if p.ctx.Err() != nil {
		return net.ErrClosed
	}
	if returnPath == nil {
		return E.New("UDP flow: missing return path")
	}
	if b.returnPath != nil && b.returnPath != returnPath {
		return E.New("UDP flow: return path already attached")
	}
	b.returnPath = returnPath
	b.mappingReturn, _ = returnPath.(tun.ReturnWithUDPMapping)
	return nil
}

func (b *portBinding) DetachReturn(returnPath tun.Return) error {
	p := b.port
	p.access.Lock()
	if b.returnPath != returnPath {
		p.access.Unlock()
		return nil
	}
	b.returnPath = nil
	b.mappingReturn = nil
	for key := range p.failures {
		if key.binding == b {
			delete(p.failures, key)
		}
	}
	flows := make([]*flow, 0, len(b.flows))
	for _, current := range b.flows {
		current.closeLocked()
		flows = append(flows, current)
	}
	p.access.Unlock()
	for _, current := range flows {
		current.closeConn()
	}
	return nil
}

// WritePackets copies packets into bounded queues. Dialing and protocol writes
// happen on per-selector workers, so a stalled server cannot block the TUN.
func (b *portBinding) WritePackets(packets [][]byte) error {
	var errs []error
	for _, packet := range packets {
		if err := b.writePacket(packet, nil); err != nil {
			errs = append(errs, err)
		}
	}
	return E.Errors(errs...)
}

// Keep the dispatcher's tuple identity through both the borrowed TUN batch and
// our owned queue. Checking a destination again after dialing could instead
// find a replacement flow and accidentally revive canceled data.
func (b *portBinding) WriteUDPFlowPackets(packets []tun.UDPFlowPacket) error {
	var errs []error
	for _, packet := range packets {
		if err := b.writePacket(packet.Packet, packet.Flow); err != nil {
			errs = append(errs, err)
		}
	}
	return E.Errors(errs...)
}

func (b *portBinding) writePacket(packet []byte, packetFlow tun.UDPFlow) error {
	if packetFlow != nil && !packetFlow.IsActive() {
		return nil
	}
	p := b.port
	source, destination, payload, ok := parseUDPPacket(packet)
	if !ok {
		return nil
	}
	p.access.Lock()
	defer p.access.Unlock()
	if p.ctx.Err() != nil {
		return net.ErrClosed
	}
	if len(payload) > p.maxQueuedBytes-p.queuedBytes {
		return E.New(p.name, " UDP flow queue byte limit reached")
	}
	key := source
	if b.mappingReturn == nil {
		// Direct Port users own their selectors, including dual-stack sockets.
		key = netip.AddrPortFrom(netip.Addr{}, source.Port())
	}
	current := b.flows[key]
	if current != nil && current.mapping != nil && current.mapping.Context().Err() != nil {
		// Mapping cancellation schedules protocol Close off the TUN reader.
		// Release its slot now even if that callback has not acquired access yet.
		current.closeLocked()
		current = nil
	}
	if current == nil {
		var mapping tun.UDPMapping
		if packetFlow != nil {
			mapping = packetFlow.UDPMapping()
		} else if b.mappingReturn != nil {
			mapping = b.mappingReturn.UDPMapping(source)
			if mapping == nil || mapping.Context().Err() != nil {
				return nil
			}
		}
		failedKey := failureKey{b, key, mapping}
		if retryAt, failed := p.failures[failedKey]; failed {
			if int64(time.Since(p.epoch)) < retryAt {
				return nil
			}
			delete(p.failures, failedKey)
		}
		if len(p.flows) >= p.maxFlows {
			return E.New(p.name, " UDP flow connection limit reached")
		}
		ctx, cancel := context.WithCancel(p.ctx)
		current = &flow{
			port:             p,
			binding:          b,
			ctx:              ctx,
			cancel:           cancel,
			selector:         source.Port(),
			key:              key,
			mapping:          mapping,
			firstDestination: M.SocksaddrFromNetIP(destination),
			returnPath:       b.returnPath,
			queue:            make(chan queuedPacket, p.queueSize),
		}
		b.flows[key] = current
		p.flows[current] = struct{}{}
		if mapping != nil {
			current.stopMapping = context.AfterFunc(mapping.Context(), current.close)
		}
		p.workers.Add(1)
		go current.run()
	}
	if len(current.queue) == cap(current.queue) {
		return E.New(p.name, " UDP flow queue full for selector ", current.selector)
	}
	// sing-tun reuses its packet storage as soon as WritePackets returns.
	buffer := buf.NewSize(current.frontHeadroom + len(payload) + current.rearHeadroom)
	buffer.Resize(current.frontHeadroom, 0)
	copy(buffer.Extend(len(payload)), payload)
	p.queuedBytes += len(payload)
	current.queue <- queuedPacket{buffer: buffer, destination: M.SocksaddrFromNetIP(destination), flow: packetFlow}
	current.touch()
	return nil
}
