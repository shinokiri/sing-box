package tun

import (
	"bytes"
	"context"

	"github.com/sagernet/sing-tun/gtcpip/header"
)

const (
	pendingFlowLimit   = 64
	pendingPacketLimit = 64
	pendingByteLimit   = 4 << 20
)

type asyncFlowState struct {
	ctx     context.Context
	handler ContextFlowHandler
	accept  func([]byte)
	pending map[flowKey]*pendingFlow
	workers int
	bytes   int
}

type pendingFlow struct {
	key     flowKey
	ctx     context.Context
	cancel  context.CancelFunc
	packets [][]byte
	count   int
	bytes   int // Includes the batch currently being delivered to the stack.
}

// EnableAsyncFlow must be called before dispatch starts. Only the first
// verdict for a tuple runs on a worker; established flows keep the inline path.
// accept delivers an owned packet to the ordinary stack without redispatching
// it here. It must finish using the packet before returning.
func (d *ForwardDispatcher) EnableAsyncFlow(ctx context.Context, accept func([]byte)) {
	if d == nil {
		return
	}
	handler, loaded := d.handler.(ContextFlowHandler)
	if !loaded {
		return
	}
	d.async = &asyncFlowState{
		ctx: ctx, handler: handler, accept: accept,
		pending: make(map[flowKey]*pendingFlow),
	}
}

func (d *ForwardDispatcher) enqueuePendingPacket(p *pendingFlow, raw []byte) {
	if p.count >= pendingPacketLimit || len(raw) > pendingByteLimit-d.async.bytes {
		d.logger.Trace("pending flow queue full, dropping packet")
		return
	}
	// The TUN/gVisor caller may immediately reuse its packet storage.
	p.packets = append(p.packets, bytes.Clone(raw))
	p.count++
	p.bytes += len(raw)
	d.async.bytes += len(raw)
}

func (d *ForwardDispatcher) startPendingFlow(key flowKey, raw []byte) {
	if d.async.ctx.Err() != nil {
		return
	}
	if d.async.workers >= pendingFlowLimit || len(raw) > pendingByteLimit-d.async.bytes {
		d.logger.Trace("pending flow limit reached, dropping packet")
		return
	}
	ctx, cancel := context.WithCancel(d.async.ctx)
	p := &pendingFlow{key: key, ctx: ctx, cancel: cancel}
	d.enqueuePendingPacket(p, raw)
	d.async.pending[key] = p
	d.async.workers++
	go d.resolvePendingFlow(p)
}

func (d *ForwardDispatcher) resolvePendingFlow(p *pendingFlow) {
	defer func() {
		p.cancel()
		d.access.Lock()
		if d.async.pending[p.key] == p {
			delete(d.async.pending, p.key)
		}
		d.async.workers--
		d.async.bytes -= p.bytes
		p.packets = nil
		p.bytes = 0
		p.count = 0
		d.access.Unlock()
	}()
	// Reset/close cancel the first packet without recycling its bytes while
	// the handler may still be reading them. It stays charged to the budget.
	d.access.Lock()
	first := p.packets[0]
	d.access.Unlock()
	packet, _ := parseForwardPacket(first)
	var payload []byte
	if packet.protocol == uint8(header.UDPProtocolNumber) {
		payload = header.UDP(packet.transport).Payload()
	}
	if p.ctx.Err() != nil {
		return
	}
	verdict := d.async.handler.JudgeFlowContext(p.ctx, packet.protocol, packet.source, packet.destination, payload)
	installed := false
	for {
		d.access.Lock()
		if d.returnPath.closed.Load() || p.ctx.Err() != nil || d.async.pending[p.key] != p {
			d.access.Unlock()
			return
		}
		packets := p.packets
		p.packets = nil
		var accepted [][]byte
		var size int
		for _, raw := range packets {
			current, _ := parseForwardPacket(raw)
			var handled bool
			if entry := d.table[p.key]; installed && entry != nil {
				handled = d.handleHit(p.key, entry, &current, raw, d.now())
			} else {
				handled = d.installVerdict(p.key, &current, raw, verdict)
				installed = true
			}
			if !handled {
				accepted = append(accepted, raw)
			}
			size += len(raw)
		}
		d.flushPackets()
		d.access.Unlock()
		// Ordinary UDP/TCP handling may perform its own connection setup. It
		// must not run with the dispatcher locked. Keep the pending entry until
		// this batch is delivered so later packets cannot overtake its first one.
		for _, raw := range accepted {
			if p.ctx.Err() != nil || d.returnPath.closed.Load() {
				return
			}
			d.async.accept(raw)
		}
		d.access.Lock()
		p.count -= len(packets)
		p.bytes -= size
		d.async.bytes -= size
		if len(p.packets) == 0 {
			if d.async.pending[p.key] == p {
				delete(d.async.pending, p.key)
			}
			d.access.Unlock()
			return
		}
		d.access.Unlock()
	}
}

// Canceled workers remain charged until their handlers return, so repeated
// resets cannot multiply live lookups. Caller holds access.
func (d *ForwardDispatcher) cancelPendingFlows() {
	if d.async != nil {
		for key, pending := range d.async.pending {
			pending.cancel()
			delete(d.async.pending, key)
		}
	}
}
