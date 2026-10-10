// Standalone, loopback-only experiment. Run under an isolated network namespace
// with netem on lo; it never changes production routes, services or credentials.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	legacy "github.com/sagernet/sing-box/cmd/policy-study/legacy_preconnect"
	"github.com/sagernet/sing-box/common/preconnect"
	"github.com/sagernet/sing-snell/snellv6"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const publicKey = "public ordinary TCP policy experiment"

type handler struct {
	N.UDPConnectionHandlerEx
	tlsConfig *tls.Config
	eofDelay  time.Duration
}

func (h *handler) NewConnectionEx(ctx context.Context, raw net.Conn, _, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	go func() {
		defer onClose(nil)
		conn := tls.Server(raw, h.tlsConfig)
		if err := conn.HandshakeContext(ctx); err != nil {
			return
		}
		request, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			return
		}
		request.Body.Close()
		// Fixed application response, independent of the transport policy.
		body := strings.Repeat("ordinary TCP experiment\n", 48)
		if request.URL.Path == "/bulk" {
			body = strings.Repeat("0123456789abcdef", 131072)
		}
		if _, err = fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body); err != nil {
			return
		}
		select {
		case <-time.After(h.eofDelay):
		case <-ctx.Done():
		}
	}()
}

type trackedConn struct {
	net.Conn
	id      int64
	used    atomic.Bool
	closed  atomic.Bool
	written atomic.Int64
}

func (c *trackedConn) Write(p []byte) (int, error) {
	c.used.Store(true)
	n, err := c.Conn.Write(p)
	c.written.Add(int64(n))
	return n, err
}
func (c *trackedConn) Close() error  { c.closed.Store(true); return c.Conn.Close() }
func (c *trackedConn) Upstream() any { return c.Conn }

type transport struct {
	N.Dialer
	mu          sync.Mutex
	connections map[string]*trackedConn
	started     atomic.Int64
	completed   atomic.Int64
	cancelled   atomic.Int64
	failed      atomic.Int64
}

func (d *transport) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	id := d.started.Add(1)
	c, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, destination.String())
	if err != nil {
		if ctx.Err() != nil {
			d.cancelled.Add(1)
		} else {
			d.failed.Add(1)
		}
		return nil, err
	}
	d.completed.Add(1)
	t := &trackedConn{Conn: c, id: id}
	d.mu.Lock()
	d.connections[c.LocalAddr().String()] = t
	d.mu.Unlock()
	return t, nil
}
func (d *transport) id(c net.Conn) int64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	if tracked := d.connections[c.LocalAddr().String()]; tracked != nil {
		return tracked.id
	}
	return -1
}

// A research policy, not a proposed configuration default: prepare only after
// at least two physical demands arrive within one second. Logical pool hits
// do not count as demands for another connection.
type preparedDialer interface {
	N.Dialer
	SetEnabled(bool)
	Reset()
	Close() error
}

type adaptive struct {
	preparedDialer
	mu   sync.Mutex
	last time.Time
}

func (d *adaptive) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.mu.Lock()
	now := time.Now()
	d.SetEnabled(!d.last.IsZero() && now.Sub(d.last) < time.Second)
	d.last = now
	d.mu.Unlock()
	return d.preparedDialer.DialContext(ctx, network, destination)
}

type observation struct {
	Index      int     `json:"index"`
	AcquireMS  float64 `json:"acquire_ms"`
	TotalMS    float64 `json:"total_ms"`
	Bytes      int64   `json:"bytes"`
	BodyMS     float64 `json:"body_ms"`
	Connection int64   `json:"connection"`
	Error      string  `json:"error,omitempty"`
}
type experiment struct {
	ctx           context.Context
	bulk          bool
	cancel        context.CancelFunc
	client        *snellv6.Client
	prepared      preparedDialer
	transport     *transport
	listener      net.Listener
	listenerDone  chan struct{}
	roots         *x509.CertPool
	serverMu      sync.Mutex
	serverSockets []net.Conn
	serverWG      sync.WaitGroup
	access        sync.Mutex
	requests      []observation
}

func start(policy string, eofDelay time.Duration, tlsConfig *tls.Config, roots *x509.CertPool) (*experiment, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	e := &experiment{ctx: ctx, cancel: cancel, roots: roots, transport: &transport{connections: make(map[string]*trackedConn)}}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		cancel()
		return nil, err
	}
	e.listener = listener
	e.listenerDone = make(chan struct{})
	h := &handler{tlsConfig: tlsConfig, eofDelay: eofDelay}
	service, err := snellv6.NewService(snellv6.ServerOptions{PSK: []byte(publicKey), Handler: h})
	if err != nil {
		listener.Close()
		cancel()
		return nil, err
	}
	e.serverWG.Add(1)
	go func() {
		defer e.serverWG.Done()
		defer close(e.listenerDone)
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			c.SetDeadline(time.Now().Add(25 * time.Second))
			e.serverMu.Lock()
			e.serverSockets = append(e.serverSockets, c)
			e.serverMu.Unlock()
			e.serverWG.Add(1)
			go func() { defer e.serverWG.Done(); defer c.Close(); service.NewConnection(ctx, c, M.Socksaddr{}, nil) }()
		}
	}()
	address := M.ParseSocksaddr(listener.Addr().String())
	var dialer N.Dialer = e.transport
	if policy == "spare" || policy == "adaptive" || policy == "race-adaptive" {
		e.prepared = legacy.New(ctx, dialer, address)
		dialer = e.prepared
		if policy != "spare" {
			e.prepared.SetEnabled(false)
			dialer = &adaptive{preparedDialer: e.prepared}
		}
	}
	if policy == "pending" || policy == "pending-adaptive" {
		e.prepared = preconnect.New(ctx, dialer, address)
		dialer = e.prepared
		if policy == "pending-adaptive" {
			e.prepared.SetEnabled(false)
			dialer = &adaptive{preparedDialer: e.prepared}
		}
	}
	e.client, err = snellv6.NewClient(snellv6.ClientOptions{PSK: []byte(publicKey), Reuse: true,
		ReuseRace: policy == "race" || policy == "race-adaptive", Dialer: dialer, Server: address})
	if err != nil {
		e.close()
		return nil, err
	}
	return e, nil
}

func (e *experiment) request(index int, hold bool) net.Conn {
	start := time.Now()
	row := observation{Index: index}
	defer func() { e.access.Lock(); e.requests = append(e.requests, row); e.access.Unlock() }()
	c, err := e.client.DialContext(e.ctx, M.ParseSocksaddr("127.0.0.1:443"))
	row.AcquireMS = float64(time.Since(start).Microseconds()) / 1000
	if err != nil {
		row.Error = err.Error()
		return nil
	}
	row.Connection = e.transport.id(c)
	c.SetDeadline(time.Now().Add(8 * time.Second))
	t := tls.Client(c, &tls.Config{RootCAs: e.roots, ServerName: "example.com"})
	if err = t.HandshakeContext(e.ctx); err == nil {
		path := "/"
		if e.bulk {
			path = "/bulk"
		}
		_, err = io.WriteString(t, "GET "+path+" HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	}
	if err == nil {
		var response *http.Response
		response, err = http.ReadResponse(bufio.NewReader(t), nil)
		if err == nil {
			bodyStart := time.Now()
			row.Bytes, err = io.Copy(io.Discard, response.Body)
			row.BodyMS = float64(time.Since(bodyStart).Microseconds()) / 1000
			if err == nil && row.Bytes != response.ContentLength {
				err = fmt.Errorf("body length mismatch")
			}
			response.Body.Close()
			if response.StatusCode != 200 {
				err = fmt.Errorf("unexpected HTTP status %d", response.StatusCode)
			}
		}
	}
	row.TotalMS = float64(time.Since(start).Microseconds()) / 1000
	if err != nil {
		row.Error = err.Error()
		c.Close()
		return nil
	}
	// Keep a logical connection busy only in the explicitly labelled saturation
	// and idle-expiry scenarios. Normal requests release it immediately.
	if hold {
		return c
	}
	c.Close()
	return nil
}

func (e *experiment) close() {
	e.cancel()
	if e.client != nil {
		e.client.Close()
	}
	if e.prepared != nil {
		e.prepared.Close()
	}
	if e.listener != nil {
		e.listener.Close()
		<-e.listenerDone
	}
	e.serverMu.Lock()
	for _, c := range e.serverSockets {
		c.Close()
	}
	e.serverMu.Unlock()
	e.serverWG.Wait()
}

func (e *experiment) output(policy, workload string, round int) map[string]any {
	var unused, bytes int64
	e.transport.mu.Lock()
	for _, c := range e.transport.connections {
		if !c.used.Load() {
			unused++
		}
		bytes += c.written.Load()
	}
	e.transport.mu.Unlock()
	sort.Slice(e.requests, func(i, j int) bool { return e.requests[i].Index < e.requests[j].Index })
	return map[string]any{"policy": policy, "workload": workload, "round": round,
		"requests": e.requests, "dial_started": e.transport.started.Load(), "dial_completed": e.transport.completed.Load(),
		"dial_cancelled": e.transport.cancelled.Load(), "dial_failed": e.transport.failed.Load(),
		"unused_completed": unused, "client_tcp_payload_bytes": bytes}
}

func main() {
	rounds := flag.Int("rounds", 2, "repetitions with rotated policy order")
	only := flag.String("workload", "", "optional single workload")
	policyList := flag.String("policies", "reuse,race,spare,adaptive,race-adaptive,pending,pending-adaptive", "policies to compare")
	flag.Parse()
	// The fixture certificate is verified by the client; there is no external
	// destination, public credential, or production service in this experiment.
	tlsFixture := httptest.NewTLSServer(http.NotFoundHandler())
	tlsConfig := tlsFixture.TLS.Clone()
	roots := x509.NewCertPool()
	roots.AddCert(tlsFixture.Certificate())
	tlsFixture.Close()
	policies := strings.Split(*policyList, ",")
	workloads := []string{"sequential-ready", "handoff", "saturated-burst", "staggered-burst", "idle-expiry", "reset", "bulk"}
	for round := range *rounds {
		for _, workload := range workloads {
			if *only != "" && workload != *only {
				continue
			}
			for index := range policies {
				policy := policies[(index+round)%len(policies)]
				eofDelay := time.Duration(0)
				if workload == "handoff" {
					eofDelay = 50 * time.Millisecond
				}
				e, err := start(policy, eofDelay, tlsConfig, roots)
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
					os.Exit(1)
				}
				switch workload {
				case "bulk":
					e.bulk = true
					for i := range 3 {
						e.request(i, false)
						time.Sleep(250 * time.Millisecond)
					}
				case "sequential-ready", "handoff":
					for i := range 8 {
						e.request(i, false)
						if workload == "sequential-ready" {
							time.Sleep(250 * time.Millisecond)
						}
					}
				case "saturated-burst", "staggered-burst":
					held := e.request(0, true)
					time.Sleep(250 * time.Millisecond)
					var wg sync.WaitGroup
					for i := 1; i <= 8; i++ {
						wg.Add(1)
						go func(i int) { defer wg.Done(); e.request(i, false) }(i)
						if workload == "staggered-burst" {
							time.Sleep(80 * time.Millisecond)
						}
					}
					wg.Wait()
					if held != nil {
						held.Close()
					}
				case "idle-expiry":
					held := e.request(0, true)
					time.Sleep(6 * time.Second)
					e.request(1, false)
					if held != nil {
						held.Close()
					}
				case "reset":
					e.request(0, false)
					time.Sleep(250 * time.Millisecond)
					e.client.Reset()
					if e.prepared != nil {
						e.prepared.Reset()
					}
					e.request(1, false)
				}
				e.close()
				json.NewEncoder(os.Stdout).Encode(e.output(policy, workload, round))
			}
		}
	}
}
