package udpflow

import (
	"context"
	"math"
	"net"
	"net/netip"
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
	defaultIdleTimeout    = 5 * time.Minute
	defaultSweepPeriod    = time.Minute
	defaultIOTimeout      = 15 * time.Second
	defaultQueueSize      = 64
	defaultMaxFlows       = 1024
	defaultMaxQueuedBytes = 4 << 20
)

var nextPortID atomic.Uint64

// PacketConnFactory creates one multi-destination packet connection for a
// selector. firstDestination can be used by protocols whose initial request
// frame requires a destination, such as VLESS XUDP. The factory must honor ctx
// cancellation, including while writing any initial handshake.
type PacketConnFactory func(ctx context.Context, firstDestination M.Socksaddr) (N.NetPacketConn, error)

type Options struct {
	Context        context.Context
	Logger         logger.ContextLogger
	Name           string
	DialPacketConn PacketConnFactory
	MTU            uint32
	IdleTimeout    time.Duration
	SweepPeriod    time.Duration
	DialTimeout    time.Duration
	WriteTimeout   time.Duration
	QueueSize      int
	MaxFlows       int
	MaxQueuedBytes int
}

var _ tun.PortWithSelectorRange = (*Port)(nil)

// Port adapts a multi-destination L4 packet connection to sing-tun's flow port.
// One packet connection is maintained per selector. Only one dispatcher may
// attach, since selector allocation is local to each dispatcher.
type Port struct {
	ctx            context.Context
	cancel         context.CancelFunc
	logger         logger.ContextLogger
	name           string
	dialPacketConn PacketConnFactory
	inet4Address   netip.Addr
	inet6Address   netip.Addr
	mtu            uint32
	idleTimeout    time.Duration
	sweepPeriod    time.Duration
	dialTimeout    time.Duration
	writeTimeout   time.Duration
	queueSize      int
	maxFlows       int
	maxQueuedBytes int

	// Never hold access across protocol or return-path I/O: WritePackets runs
	// on the TUN reader, which must also serve unrelated flows.
	access      sync.Mutex
	returnPath  tun.Return
	flows       map[uint16]*flow
	queuedBytes int

	closeOnce sync.Once
	workers   sync.WaitGroup
}

type queuedPacket struct {
	buffer      *buf.Buffer
	destination M.Socksaddr
}

type flow struct {
	port             *Port
	ctx              context.Context
	cancel           context.CancelFunc
	selector         uint16
	firstDestination M.Socksaddr
	returnPath       tun.Return
	queue            chan queuedPacket
	lastActivity     atomic.Int64

	connAccess sync.Mutex
	packetConn N.NetPacketConn
}

func New(options Options) (*Port, error) {
	if options.DialPacketConn == nil {
		return nil, E.New("UDP flow: missing packet connection factory")
	}
	if options.Context == nil {
		options.Context = context.Background()
	}
	if options.Logger == nil {
		options.Logger = logger.NOP()
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
	if options.DialTimeout <= 0 {
		options.DialTimeout = defaultIOTimeout
	}
	if options.WriteTimeout <= 0 {
		options.WriteTimeout = defaultIOTimeout
	}
	if options.QueueSize <= 0 {
		options.QueueSize = defaultQueueSize
	}
	if options.MaxFlows <= 0 {
		options.MaxFlows = defaultMaxFlows
	}
	if options.MaxQueuedBytes <= 0 {
		options.MaxQueuedBytes = defaultMaxQueuedBytes
	}
	id := nextPortID.Add(1)
	if id >= 1<<24 {
		return nil, E.New("UDP flow: internal port addresses exhausted")
	}
	ctx, cancel := context.WithCancel(options.Context)
	port := &Port{
		ctx:            ctx,
		cancel:         cancel,
		logger:         options.Logger,
		name:           options.Name,
		dialPacketConn: options.DialPacketConn,
		// These addresses are only used between the dispatcher and this port;
		// they never appear on the proxy connection or the TUN return packet.
		// Distinct addresses keep independently allocated selectors disjoint.
		inet4Address:   netip.AddrFrom4([4]byte{127, byte(id >> 16), byte(id >> 8), byte(id)}),
		inet6Address:   netip.AddrFrom16([16]byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(id >> 16), byte(id >> 8), byte(id)}),
		mtu:            options.MTU,
		idleTimeout:    options.IdleTimeout,
		sweepPeriod:    options.SweepPeriod,
		dialTimeout:    options.DialTimeout,
		writeTimeout:   options.WriteTimeout,
		queueSize:      options.QueueSize,
		maxFlows:       options.MaxFlows,
		maxQueuedBytes: options.MaxQueuedBytes,
		flows:          make(map[uint16]*flow),
	}
	port.workers.Add(1)
	go port.sweepLoop()
	return port, nil
}

func (p *Port) PortAddresses() (netip.Addr, netip.Addr) {
	return p.inet4Address, p.inet6Address
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
	p.access.Lock()
	defer p.access.Unlock()
	if p.ctx.Err() != nil {
		return net.ErrClosed
	}
	if returnPath == nil {
		return E.New("UDP flow: missing return path")
	}
	if p.returnPath != nil && p.returnPath != returnPath {
		return E.New("UDP flow: return path already attached")
	}
	p.returnPath = returnPath
	return nil
}

func (p *Port) DetachReturn(returnPath tun.Return) error {
	p.access.Lock()
	if p.returnPath != returnPath {
		p.access.Unlock()
		return nil
	}
	p.returnPath = nil
	flows := p.takeFlowsLocked()
	p.access.Unlock()
	for _, current := range flows {
		current.closeConn()
	}
	return nil
}

// WritePackets copies packets into bounded queues. Dialing and protocol writes
// happen on per-selector workers, so a stalled server cannot block the TUN.
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
	p.access.Lock()
	defer p.access.Unlock()
	if p.ctx.Err() != nil {
		return net.ErrClosed
	}
	if len(payload) > p.maxQueuedBytes-p.queuedBytes {
		return E.New(p.name, " UDP flow queue byte limit reached")
	}
	current := p.flows[source.Port()]
	if current == nil {
		if len(p.flows) >= p.maxFlows {
			return E.New(p.name, " UDP flow connection limit reached")
		}
		ctx, cancel := context.WithCancel(p.ctx)
		current = &flow{
			port:             p,
			ctx:              ctx,
			cancel:           cancel,
			selector:         source.Port(),
			firstDestination: M.SocksaddrFromNetIP(destination),
			returnPath:       p.returnPath,
			queue:            make(chan queuedPacket, p.queueSize),
		}
		p.flows[current.selector] = current
		p.workers.Add(1)
		go current.run()
	}
	if len(current.queue) == cap(current.queue) {
		return E.New(p.name, " UDP flow queue full for selector ", current.selector)
	}
	// sing-tun reuses its packet storage as soon as WritePackets returns.
	buffer := buf.NewSize(len(payload))
	copy(buffer.Extend(len(payload)), payload)
	p.queuedBytes += len(payload)
	current.queue <- queuedPacket{buffer, M.SocksaddrFromNetIP(destination)}
	current.touch()
	return nil
}

func (f *flow) touch() {
	f.lastActivity.Store(time.Now().UnixNano())
}

func (f *flow) run() {
	defer f.port.workers.Done()
	defer func() {
		f.close()
		// close prevents any further enqueues before draining owned buffers.
		for {
			select {
			case packet := <-f.queue:
				f.releasePacket(packet)
			default:
				return
			}
		}
	}()

	dialCtx, cancel := context.WithTimeout(f.ctx, f.port.dialTimeout)
	packetConn, err := f.port.dialPacketConn(dialCtx, f.firstDestination)
	if err == nil && dialCtx.Err() != nil {
		packetConn.Close()
		err = dialCtx.Err()
	}
	cancel()
	if err != nil {
		f.logError("dial", err)
		return
	}
	f.connAccess.Lock()
	if f.ctx.Err() != nil {
		f.connAccess.Unlock()
		packetConn.Close()
		return
	}
	f.packetConn = packetConn
	f.connAccess.Unlock()

	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		f.readLoop(packetConn)
	}()
	defer func() {
		f.close()
		<-readDone
	}()

	for {
		select {
		case <-f.ctx.Done():
			return
		case packet := <-f.queue:
			if f.ctx.Err() != nil {
				f.releasePacket(packet)
				return
			}
			err = f.writePacket(packetConn, packet)
			if err != nil {
				f.logError("write", err)
				return
			}
		}
	}
}

func (f *flow) writePacket(packetConn N.NetPacketConn, packet queuedPacket) error {
	size := packet.buffer.Len()
	// Calculate headroom on the writer: XUDP changes its requirements after
	// the first frame, and writers are not universally concurrent.
	frontHeadroom := N.CalculateFrontHeadroom(packetConn)
	rearHeadroom := N.CalculateRearHeadroom(packetConn)
	buffer := buf.NewSize(frontHeadroom + size + rearHeadroom)
	buffer.Resize(frontHeadroom, 0)
	copy(buffer.Extend(size), packet.buffer.Bytes())
	packet.buffer.Release()
	// Keep in-flight bytes charged to the queue budget until the write ends,
	// but do not retain a second payload copy while waiting on the network.
	defer f.port.releaseQueuedBytes(size)
	// Some protocols read a handshake inside WritePacket. A write-only
	// deadline cannot interrupt that read; closing can interrupt both.
	timer := time.AfterFunc(f.port.writeTimeout, func() {
		f.logError("write", context.DeadlineExceeded)
		f.close()
	})
	defer timer.Stop()
	return packetConn.WritePacket(buffer, packet.destination)
}

func (f *flow) releasePacket(packet queuedPacket) {
	size := packet.buffer.Len()
	packet.buffer.Release()
	f.port.releaseQueuedBytes(size)
}

func (p *Port) releaseQueuedBytes(size int) {
	p.access.Lock()
	p.queuedBytes -= size
	p.access.Unlock()
}

func (f *flow) readLoop(packetConn N.NetPacketConn) {
	defer f.close()
	for {
		buffer := buf.NewSize(65535)
		source, err := packetConn.ReadPacket(buffer)
		if err != nil {
			buffer.Release()
			f.logError("read", err)
			return
		}
		if f.ctx.Err() != nil {
			buffer.Release()
			return
		}
		f.touch()
		err = f.returnPacket(source, buffer.Bytes())
		buffer.Release()
		if err != nil {
			f.logError("return", err)
		}
	}
}

func (f *flow) logError(operation string, err error) {
	if f.ctx.Err() == nil {
		f.port.logger.DebugContext(f.ctx, operation, " ", f.port.name, " UDP flow ", f.selector, ": ", err)
	}
}

func (f *flow) returnPacket(source M.Socksaddr, payload []byte) error {
	if f.returnPath == nil || f.ctx.Err() != nil {
		return nil
	}
	address := f.port.inet6Address
	if source.Addr.Unmap().Is4() {
		address = f.port.inet4Address
	}
	packet, err := buildUDPResponse(f.returnPath.ReturnHeadroom(), source, netip.AddrPortFrom(address, f.selector), payload)
	if err != nil {
		return err
	}
	// Keep the return path captured at creation. A detached flow must never
	// send a late response through a newly attached dispatcher's selectors.
	f.returnPath.ReturnPackets([][]byte{packet})
	return nil
}

func (p *Port) sweepLoop() {
	defer p.workers.Done()
	ticker := time.NewTicker(p.sweepPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			p.sweep()
		case <-p.ctx.Done():
			p.stop()
			return
		}
	}
}

func (p *Port) sweep() {
	deadline := time.Now().Add(-p.idleTimeout).UnixNano()
	var expired []*flow
	p.access.Lock()
	for _, current := range p.flows {
		if current.lastActivity.Load() < deadline {
			current.closeLocked()
			expired = append(expired, current)
		}
	}
	p.access.Unlock()
	for _, current := range expired {
		current.closeConn()
	}
}

func (f *flow) closeLocked() {
	f.cancel()
	if f.port.flows[f.selector] == f {
		delete(f.port.flows, f.selector)
	}
}

func (f *flow) closeConn() {
	f.connAccess.Lock()
	packetConn := f.packetConn
	f.packetConn = nil
	f.connAccess.Unlock()
	if packetConn != nil {
		packetConn.Close()
	}
}

func (f *flow) close() {
	f.port.access.Lock()
	f.closeLocked()
	f.port.access.Unlock()
	f.closeConn()
}

func (p *Port) takeFlowsLocked() []*flow {
	flows := make([]*flow, 0, len(p.flows))
	for _, current := range p.flows {
		current.closeLocked()
		flows = append(flows, current)
	}
	return flows
}

func (p *Port) Reset() {
	p.access.Lock()
	flows := p.takeFlowsLocked()
	p.access.Unlock()
	for _, current := range flows {
		current.closeConn()
	}
}

func (p *Port) stop() {
	p.closeOnce.Do(func() {
		p.access.Lock()
		p.cancel()
		flows := p.takeFlowsLocked()
		p.access.Unlock()
		for _, current := range flows {
			current.closeConn()
		}
	})
}

func (p *Port) Close() error {
	p.stop()
	p.workers.Wait()
	return nil
}
