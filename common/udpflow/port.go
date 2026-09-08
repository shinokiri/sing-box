package udpflow

import (
	"context"
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

// PacketConnFactory creates one multi-destination packet connection for a
// selector. firstDestination can be used by protocols whose initial request
// frame requires a destination, such as VLESS XUDP. The factory must honor ctx
// cancellation, including while writing any initial handshake. After a
// successful dial, ctx remains valid until the flow closes so transports may
// use it for the lifetime of their streams.
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
// Each inbound has its own selectors and return path, while association and
// payload limits apply to the whole outbound.
type Port struct {
	*portBinding
	ctx            context.Context
	cancel         context.CancelFunc
	logger         logger.ContextLogger
	name           string
	dialPacketConn PacketConnFactory
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
	bindings    map[string]*portBinding
	flows       map[*flow]struct{}
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
	binding          *portBinding
	ctx              context.Context
	cancel           context.CancelFunc
	selector         uint16
	firstDestination M.Socksaddr
	returnPath       tun.Return
	queue            chan queuedPacket
	lastActivity     atomic.Int64

	// The worker publishes framing requirements under port.access. Enqueue
	// reserves this space without calling into a concurrently active writer.
	frontHeadroom int
	rearHeadroom  int
	writeTimer    *time.Timer // owned by the writer, stopped between packets

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
	ctx, cancel := context.WithCancel(options.Context)
	port := &Port{
		ctx:            ctx,
		cancel:         cancel,
		logger:         options.Logger,
		name:           options.Name,
		dialPacketConn: options.DialPacketConn,
		mtu:            options.MTU,
		idleTimeout:    options.IdleTimeout,
		sweepPeriod:    options.SweepPeriod,
		dialTimeout:    options.DialTimeout,
		writeTimeout:   options.WriteTimeout,
		queueSize:      options.QueueSize,
		maxFlows:       options.MaxFlows,
		maxQueuedBytes: options.MaxQueuedBytes,
		bindings:       make(map[string]*portBinding),
		flows:          make(map[*flow]struct{}),
	}
	var err error
	port.portBinding, err = port.newBinding()
	if err != nil {
		cancel()
		return nil, err
	}
	port.workers.Add(1)
	go port.sweepLoop()
	return port, nil
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

	// HTTP/2 and gRPC keep the dial context on their established streams.
	// Stop only the setup timer on success; cancel the context on flow exit.
	dialCtx, cancel := context.WithCancelCause(f.ctx)
	defer cancel(nil)
	dialTimer := time.AfterFunc(f.port.dialTimeout, func() { cancel(context.DeadlineExceeded) })
	packetConn, err := f.port.dialPacketConn(dialCtx, f.firstDestination)
	if !dialTimer.Stop() {
		// The callback may have started without canceling the context yet.
		cancel(context.DeadlineExceeded)
	}
	if err == nil && dialCtx.Err() != nil {
		packetConn.Close()
		err = context.Cause(dialCtx)
	}
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
	if frontHeadroom != f.frontHeadroom || rearHeadroom != f.rearHeadroom {
		f.port.access.Lock()
		f.frontHeadroom, f.rearHeadroom = frontHeadroom, rearHeadroom
		f.port.access.Unlock()
	}
	buffer := packet.buffer
	if buffer.Start() < frontHeadroom || buffer.FreeLen() < rearHeadroom {
		// Packets queued before dialing or a framing change may need more
		// space. Established flows normally pass their owned buffer through.
		buffer = buf.NewSize(frontHeadroom + size + rearHeadroom)
		buffer.Resize(frontHeadroom, 0)
		copy(buffer.Extend(size), packet.buffer.Bytes())
		packet.buffer.Release()
	}
	// Keep in-flight bytes charged to the queue budget until the write ends,
	// but do not retain a second payload copy while waiting on the network.
	defer f.port.releaseQueuedBytes(size)
	// Some protocols read a handshake inside WritePacket. A write-only
	// deadline cannot interrupt that read; closing can interrupt both.
	if f.writeTimer == nil {
		f.writeTimer = time.AfterFunc(f.port.writeTimeout, func() {
			f.logError("write", context.DeadlineExceeded)
			f.close()
		})
	} else {
		f.writeTimer.Reset(f.port.writeTimeout)
	}
	err := packetConn.WritePacket(buffer, packet.destination)
	if !f.writeTimer.Stop() && err == nil {
		// An expired callback may still be starting. End this association;
		// never reuse its timer for another write while that callback can run.
		err = context.DeadlineExceeded
	}
	return err
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
	buffer := buf.NewSize(65535)
	defer buffer.Release()
	for {
		buffer.Resize(0, 0)
		source, err := packetConn.ReadPacket(buffer)
		if err != nil {
			f.logError("read", err)
			return
		}
		if f.ctx.Err() != nil {
			return
		}
		f.touch()
		err = f.returnPacket(source, buffer.Bytes())
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
	address := f.binding.inet6Address
	if source.Addr.Unmap().Is4() {
		address = f.binding.inet4Address
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
	for current := range p.flows {
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
	delete(f.port.flows, f)
	if f.binding.flows[f.selector] == f {
		delete(f.binding.flows, f.selector)
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
	for current := range p.flows {
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
