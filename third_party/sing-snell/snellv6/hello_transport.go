package snellv6

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	helloColdBudget     = 536 - 40
	helloColdIPv6Budget = 1220 - 40
	helloMaxBudget      = 4181
	helloCacheTTL       = 5 * time.Minute
	helloCacheSize      = 64
)

// HelloFrameInfo is optional diagnostic metadata. It never contains a key or
// application data. Acceptance of SYN data must be verified separately.
type HelloFrameInfo struct {
	Budget, WireBytes, OriginalBytes, InitialWriteBytes int
	Mode                                                int
	BudgetSource                                        string
}

type helloCapacity struct {
	bytes   int
	expires time.Time
}

type HelloTransportOptions struct {
	// InitialSYNDataLimit is an explicit, previously measured path assumption,
	// used only without a current peer observation. Zero uses the RFC7413
	// family default. It is not negotiated and must include the carrier bytes.
	InitialSYNDataLimit int
}

// HelloTransport frames only the first physical write of a default-mode Snell
// v6 connection. It preserves the original encryption and record sequence.
// This private carrier is not a TLS session.
type HelloTransport struct {
	codec               *helloRecordCodec
	initialSYNDataLimit int
	mu                  sync.Mutex
	generation          uint64
	capacities          map[string]helloCapacity
	now                 func() time.Time
	// OnFirstFrame must be configured before using the transport.
	OnFirstFrame func(HelloFrameInfo)
}

func NewHelloTransport(psk []byte) (*HelloTransport, error) {
	return NewHelloTransportWithOptions(psk, HelloTransportOptions{})
}

func NewHelloTransportWithOptions(psk []byte, options HelloTransportOptions) (*HelloTransport, error) {
	if len(psk) < 12 || len(psk) > 255 {
		return nil, fmt.Errorf("snell: hello framing requires a 12..255 byte PSK")
	}
	if n := options.InitialSYNDataLimit; n != 0 && (n < helloMinBudget || n > helloMaxBudget) {
		return nil, fmt.Errorf("snell: initial SYN data limit must be zero or %d..%d", helloMinBudget, helloMaxBudget)
	}
	return &HelloTransport{codec: newHelloRecordCodec(psk), initialSYNDataLimit: options.InitialSYNDataLimit, capacities: make(map[string]helloCapacity), now: time.Now}, nil
}

func (t *HelloTransport) initialBudget(endpoint string) (int, string) {
	if t.initialSYNDataLimit != 0 {
		return t.initialSYNDataLimit, "configured_initial_limit"
	}
	if peer, err := netip.ParseAddrPort(endpoint); err == nil && peer.Addr().Unmap().Is6() {
		return helloColdIPv6Budget, "cold_ipv6_estimate"
	}
	return helloColdBudget, "cold_estimate"
}

// Reset invalidates observations on a network change. A connection created in
// an earlier generation cannot repopulate the new network's cache.
func (t *HelloTransport) Reset() {
	t.mu.Lock()
	t.generation++
	clear(t.capacities)
	t.mu.Unlock()
}

func (t *HelloTransport) Wrap(conn net.Conn, endpoint string) net.Conn {
	t.mu.Lock()
	generation := t.generation
	t.mu.Unlock()
	return t.wrap(conn, endpoint, generation)
}

func (t *HelloTransport) wrap(conn net.Conn, endpoint string, generation uint64) net.Conn {
	return &helloConn{Conn: conn, transport: t, endpoint: helloEndpoint(conn, endpoint), generation: generation}
}

func (t *HelloTransport) WrapDialer(upstream N.Dialer) N.Dialer {
	return &helloDialer{Dialer: upstream, transport: t}
}

type helloDialer struct {
	N.Dialer
	transport *HelloTransport
}

func (d *helloDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) != N.NetworkTCP {
		return d.Dialer.DialContext(ctx, network, destination)
	}
	// Associate the dial with its starting network. Reset may run while the
	// upstream resolves or connects; that socket must not seed the new cache.
	d.transport.mu.Lock()
	generation := d.transport.generation
	d.transport.mu.Unlock()
	conn, err := d.Dialer.DialContext(ctx, network, destination)
	if err != nil {
		return nil, err
	}
	return d.transport.wrap(conn, destination.String(), generation), nil
}

// DialDestination is supplied by a deferred dialer before it has a TCP socket.
// It distinguishes resolved IPv4/IPv6 peers without causing an extra dial.
func helloEndpoint(conn net.Conn, fallback string) string {
	for depth := 0; conn != nil && depth < 8; depth++ {
		var addr net.Addr
		if deferred, ok := conn.(interface{ DialDestination() net.Addr }); ok {
			addr = deferred.DialDestination()
		} else {
			addr = conn.RemoteAddr()
		}
		if addr != nil {
			if host, port, err := net.SplitHostPort(addr.String()); err == nil && host != "" && port != "0" {
				return addr.String()
			}
		}
		u, ok := conn.(common.WithUpstream)
		if !ok {
			break
		}
		conn, _ = u.Upstream().(net.Conn)
	}
	return fallback
}

func (t *HelloTransport) remember(endpoint string, generation uint64, capacity int) bool {
	if capacity < 86 {
		return false
	}
	capacity = min(capacity, helloMaxBudget)
	t.mu.Lock()
	defer t.mu.Unlock()
	if generation != t.generation {
		return false
	}
	now := t.now()
	if previous, ok := t.capacities[endpoint]; ok && previous.expires.After(now) {
		capacity = min(capacity, previous.bytes)
	}
	if _, exists := t.capacities[endpoint]; !exists && len(t.capacities) >= helloCacheSize {
		var oldest string
		var expiry time.Time
		for key, entry := range t.capacities {
			if oldest == "" || entry.expires.Before(expiry) {
				oldest, expiry = key, entry.expires
			}
		}
		delete(t.capacities, oldest)
	}
	t.capacities[endpoint] = helloCapacity{bytes: capacity, expires: now.Add(helloCacheTTL)}
	return true
}

func (t *HelloTransport) budget(conn net.Conn, endpoint string, generation uint64) (int, string) {
	negotiated, routeLimit := helloSocketCapacity(conn)
	if negotiated > 0 {
		t.remember(endpoint, generation, negotiated)
		return min(negotiated, helloMaxBudget), "negotiated"
	}
	t.mu.Lock()
	entry, found := t.capacities[endpoint]
	valid := generation == t.generation && found && entry.expires.After(t.now())
	t.mu.Unlock()
	budget, source := t.initialBudget(endpoint)
	if valid {
		budget, source = entry.bytes, "observed_peer"
	}
	if routeLimit > 0 {
		budget = min(budget, routeLimit)
	}
	// RFC7413 section4.1.3 uses536 IPv4 /1220 IPv6 when peer MSS is unknown;
	// reserve the maximum40 TCP option bytes. This is an estimate, not a lower
	// bound on peer MSS. An explicit initial limit is a measured path assumption,
	// never an observation, and does not override learned peer or route limits.
	return budget, source
}

type helloConn struct {
	net.Conn
	transport  *HelloTransport
	endpoint   string
	generation uint64
	mu         sync.Mutex
	sent       atomic.Bool
	observed   atomic.Bool
	err        error
	vectorised N.VectorisedWriter
}

func (c *helloConn) observe() {
	if capacity, _ := helloSocketCapacity(c.Conn); capacity >= 86 {
		c.transport.remember(c.endpoint, c.generation, capacity)
		// An older connection must not repopulate a new network's cache, but
		// it also must not keep polling TCP_INFO on every subsequent read.
		c.observed.Store(true)
	}
}

func (c *helloConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writeLocked(p)
}

func (c *helloConn) writeLocked(p []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	if len(p) == 0 {
		return 0, nil
	}
	if c.sent.Load() {
		return c.Conn.Write(p)
	}
	budget, source := c.transport.budget(c.Conn, c.endpoint, c.generation)
	packed, take, mode, err := c.transport.codec.Pack(p, budget-85)
	if err != nil {
		return c.fail(0, err)
	}
	wire, err := helloRecord(packed, true)
	if err != nil {
		return c.fail(0, err)
	}
	if len(wire) > budget {
		return c.fail(0, fmt.Errorf("snell: hello exceeds selected SYN capacity"))
	}
	n, err := c.Conn.Write(wire)
	if err != nil {
		return c.fail(0, err)
	}
	if n != len(wire) {
		return c.fail(0, io.ErrShortWrite)
	}
	if take < len(p) {
		n, err = c.Conn.Write(p[take:])
		if err != nil {
			return c.fail(take+n, err)
		}
		if n != len(p)-take {
			return c.fail(take+n, io.ErrShortWrite)
		}
	}
	c.observe()
	c.vectorised = bufio.NewVectorisedWriter(c.Conn)
	c.sent.Store(true)
	if report := c.transport.OnFirstFrame; report != nil {
		report(HelloFrameInfo{Budget: budget, WireBytes: len(wire), OriginalBytes: take, InitialWriteBytes: len(p), Mode: mode, BudgetSource: source})
	}
	return len(p), nil
}

func (c *helloConn) fail(n int, err error) (int, error) {
	c.err = err
	c.Conn.Close()
	return n, err
}

func (c *helloConn) WriteBuffer(buffer *buf.Buffer) error {
	defer buffer.Release()
	_, err := c.Write(buffer.Bytes())
	return err
}

func (c *helloConn) WriteVectorised(buffers []*buf.Buffer) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		buf.ReleaseMulti(buffers)
		return c.err
	}
	if c.sent.Load() {
		return c.vectorised.WriteVectorised(buffers)
	}
	defer buf.ReleaseMulti(buffers)
	if buf.LenMulti(buffers) == 0 {
		return nil
	}
	if len(buffers) == 1 {
		_, err := c.writeLocked(buffers[0].Bytes())
		return err
	}
	// The initial salt/header/body may be separate buffers. Coalesce this one
	// physical write so the encoder sees a complete first record. Later vectors
	// keep the existing socket writev path and buffer ownership behavior.
	joined := buf.NewSize(buf.LenMulti(buffers))
	defer joined.Release()
	for _, buffer := range buffers {
		_, _ = joined.Write(buffer.Bytes())
	}
	_, err := c.writeLocked(joined.Bytes())
	return err
}

func (c *helloConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 && !c.observed.Load() {
		c.observe()
	}
	return n, err
}

func (c *helloConn) Upstream() any           { return c.Conn }
func (c *helloConn) ReaderReplaceable() bool { return c.sent.Load() && c.observed.Load() }
func (c *helloConn) WriterReplaceable() bool { return c.sent.Load() }
func (c *helloConn) NeedHandshake() bool     { return !c.sent.Load() }
