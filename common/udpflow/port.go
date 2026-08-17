package udpflow

import (
	"context"
	"math"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	defaultIdleTimeout = 5 * time.Minute
	defaultSweepPeriod = time.Minute
)

// PacketConnFactory creates one multi-destination packet connection for a
// selector. firstDestination is the first real destination assigned to that
// selector and can be used by protocols whose initial request frame requires a
// destination, such as VLESS XUDP.
type PacketConnFactory func(ctx context.Context, firstDestination M.Socksaddr) (N.NetPacketConn, error)

type Options struct {
	Context        context.Context
	Logger         logger.ContextLogger
	Name           string
	DialPacketConn PacketConnFactory
	MTU            uint32
	IdleTimeout    time.Duration
	SweepPeriod    time.Duration
}

var _ tun.PortWithSelectorRange = (*Port)(nil)

// Port adapts a multi-destination L4 packet connection to sing-tun's flow
// port. One packet connection is maintained per selector, allowing different
// destinations from the same client UDP socket to share one protocol-level
// association while sing-tun performs per-flow DNAT and reverse rewriting.
type Port struct {
	ctx            context.Context
	logger         logger.ContextLogger
	name           string
	dialPacketConn PacketConnFactory
	mtu            uint32
	idleTimeout    time.Duration
	sweepPeriod    time.Duration

	returnAccess sync.RWMutex
	returnPaths  []tun.Return

	flowAccess sync.Mutex
	flows      map[uint16]*flow

	closeOnce sync.Once
	closed    chan struct{}
	readGroup sync.WaitGroup
}

type flow struct {
	port         *Port
	selector     uint16
	packetConn   N.NetPacketConn
	writeAccess  sync.Mutex
	lastActivity atomic.Int64
	closed       atomic.Bool
}

func New(options Options) (*Port, error) {
	if options.DialPacketConn == nil {
		return nil, E.New("UDP flow: missing packet connection factory")
	}
	if options.Context == nil {
		options.Context = context.Background()
	}
	if options.Name == "" {
		options.Name = "proxy"
	}
	if options.IdleTimeout <= 0 {
		options.IdleTimeout = defaultIdleTimeout
	}
	if options.SweepPeriod <= 0 {
		options.SweepPeriod = defaultSweepPeriod
	}
	port := &Port{
		ctx:            options.Context,
		logger:         options.Logger,
		name:           options.Name,
		dialPacketConn: options.DialPacketConn,
		mtu:            options.MTU,
		idleTimeout:    options.IdleTimeout,
		sweepPeriod:    options.SweepPeriod,
		flows:          make(map[uint16]*flow),
		closed:         make(chan struct{}),
	}
	go port.sweepLoop()
	return port, nil
}

func (p *Port) PortAddresses() (netip.Addr, netip.Addr) {
	return netip.IPv4Unspecified(), netip.IPv6Unspecified()
}

func (p *Port) PortMTU() uint32 {
	return p.mtu
}

func (p *Port) PortSelectorRange() (uint16, uint16) {
	// Preserve the application's UDP source port whenever the reverse-flow key
	// is unambiguous. sing-tun allocates another selector only on a collision.
	return 1, math.MaxUint16
}

func (p *Port) AttachReturn(returnPath tun.Return) error {
	p.returnAccess.Lock()
	defer p.returnAccess.Unlock()
	if slices.Contains(p.returnPaths, returnPath) {
		return nil
	}
	p.returnPaths = append(p.returnPaths[:len(p.returnPaths):len(p.returnPaths)], returnPath)
	return nil
}

func (p *Port) DetachReturn(returnPath tun.Return) error {
	p.returnAccess.Lock()
	defer p.returnAccess.Unlock()
	returnPaths := make([]tun.Return, 0, len(p.returnPaths))
	for _, existing := range p.returnPaths {
		if existing != returnPath {
			returnPaths = append(returnPaths, existing)
		}
	}
	p.returnPaths = returnPaths
	return nil
}

func (p *Port) WritePackets(packets [][]byte) error {
	var errs []error
	for _, packet := range packets {
		if err := p.writePacket(packet); err != nil {
			errs = append(errs, err)
		}
	}
	return E.Errors(errs...)
}

func (p *Port) writePacket(packet []byte) error {
	source, destination, payload, ok := parseUDPPacket(packet)
	if !ok {
		return nil
	}
	destinationAddress := M.SocksaddrFromNetIP(destination)
	currentFlow, err := p.flowFor(source.Port(), destinationAddress)
	if err != nil {
		return E.Cause(err, "create ", p.name, " UDP flow for selector ", source.Port())
	}
	currentFlow.touch()
	frontHeadroom := N.CalculateFrontHeadroom(currentFlow.packetConn)
	rearHeadroom := N.CalculateRearHeadroom(currentFlow.packetConn)
	buffer := buf.NewSize(frontHeadroom + len(payload) + rearHeadroom)
	if frontHeadroom > 0 {
		buffer.Resize(frontHeadroom, 0)
	}
	_, err = buffer.Write(payload)
	if err != nil {
		buffer.Release()
		return err
	}
	// XUDP's first frame changes connection state and protocol writers are not
	// universally thread-safe. Serialize writes for each selector while still
	// allowing different selectors to progress independently.
	currentFlow.writeAccess.Lock()
	err = currentFlow.packetConn.WritePacket(buffer, destinationAddress)
	currentFlow.writeAccess.Unlock()
	return err
}

func (p *Port) flowFor(selector uint16, firstDestination M.Socksaddr) (*flow, error) {
	p.flowAccess.Lock()
	defer p.flowAccess.Unlock()
	select {
	case <-p.closed:
		return nil, E.New(p.name, " UDP flow port is closed")
	default:
	}
	if current := p.flows[selector]; current != nil && !current.closed.Load() {
		return current, nil
	}
	packetConn, err := p.dialPacketConn(p.ctx, firstDestination)
	if err != nil {
		return nil, err
	}
	current := &flow{port: p, selector: selector, packetConn: packetConn}
	current.touch()
	p.flows[selector] = current
	p.readGroup.Add(1)
	go current.readLoop()
	return current, nil
}

func (f *flow) touch() {
	f.lastActivity.Store(time.Now().UnixNano())
}

func (f *flow) readLoop() {
	defer f.port.readGroup.Done()
	defer f.close()
	for {
		buffer := buf.NewSize(65535)
		source, err := f.packetConn.ReadPacket(buffer)
		if err != nil {
			buffer.Release()
			if !f.closed.Load() {
				f.port.logger.DebugContext(f.port.ctx, f.port.name, " UDP flow ", f.selector, " closed: ", err)
			}
			return
		}
		f.touch()
		err = f.port.returnPacket(f.selector, source, buffer.Bytes())
		buffer.Release()
		if err != nil {
			f.port.logger.DebugContext(f.port.ctx, "return ", f.port.name, " UDP flow ", f.selector, ": ", err)
		}
	}
}

func (p *Port) returnPacket(selector uint16, source M.Socksaddr, payload []byte) error {
	if !source.IsIP() {
		return E.New("invalid ", p.name, " UDP response source: ", source)
	}
	p.returnAccess.RLock()
	returnPaths := append([]tun.Return(nil), p.returnPaths...)
	p.returnAccess.RUnlock()
	for _, returnPath := range returnPaths {
		packet, err := buildUDPResponse(returnPath.ReturnHeadroom(), source, selector, payload)
		if err != nil {
			return err
		}
		if len(returnPath.ReturnPackets([][]byte{packet})) == 0 {
			return nil
		}
	}
	return nil
}

func (p *Port) sweepLoop() {
	ticker := time.NewTicker(p.sweepPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			p.sweep()
		case <-p.closed:
			return
		}
	}
}

func (p *Port) sweep() {
	deadline := time.Now().Add(-p.idleTimeout).UnixNano()
	var expired []*flow
	p.flowAccess.Lock()
	for selector, current := range p.flows {
		if current.closed.Load() || current.lastActivity.Load() < deadline {
			delete(p.flows, selector)
			expired = append(expired, current)
		}
	}
	p.flowAccess.Unlock()
	for _, current := range expired {
		current.close()
	}
}

func (p *Port) removeFlow(current *flow) {
	p.flowAccess.Lock()
	if p.flows[current.selector] == current {
		delete(p.flows, current.selector)
	}
	p.flowAccess.Unlock()
}

func (f *flow) close() {
	if !f.closed.CompareAndSwap(false, true) {
		return
	}
	f.port.removeFlow(f)
	f.packetConn.Close()
}

func (p *Port) Reset() {
	p.closeFlows()
}

func (p *Port) closeFlows() {
	p.flowAccess.Lock()
	flows := make([]*flow, 0, len(p.flows))
	for selector, current := range p.flows {
		delete(p.flows, selector)
		flows = append(flows, current)
	}
	p.flowAccess.Unlock()
	for _, current := range flows {
		current.close()
	}
}

func (p *Port) Close() error {
	p.closeOnce.Do(func() {
		close(p.closed)
		p.closeFlows()
	})
	p.readGroup.Wait()
	return nil
}
