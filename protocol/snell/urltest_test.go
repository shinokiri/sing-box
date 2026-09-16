package snell

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-snell/snellv6"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

// Delay the first server EOF after its HEAD response. The measured request
// must reuse that session. The lazy fixture models TFO moving establishment
// into the first Write; real socket controls are tested in common/dialer.
func TestURLTestReusesWarmSnellSession(t *testing.T) {
	for _, mode := range []snellv6.Mode{snellv6.ModeDefault, snellv6.ModeUnshaped} {
		for _, lazy := range []bool{false, true} {
			t.Run(fmt.Sprintf("mode=%d/lazy=%v", mode, lazy), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				handler := &urlTestHandler{eofDelay: 200 * time.Millisecond}
				service, err := snellv6.NewService(snellv6.ServerOptions{
					PSK: []byte("urltest-fixture-key"), Mode: mode, Handler: handler,
				})
				if err != nil {
					t.Fatal(err)
				}
				transport := &urlTestTransport{service: service, lazy: lazy}
				t.Cleanup(transport.Close)
				client, err := snellv6.NewClient(snellv6.ClientOptions{
					PSK: []byte("urltest-fixture-key"), Mode: mode, Reuse: true,
					Dialer: transport, Server: M.ParseSocksaddr("127.0.0.1:12345"),
				})
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				client.SetKeepIdleConnections(false)
				node := &Outbound{
					Adapter: outbound.NewAdapter(C.TypeSnell, "fixture", []string{N.NetworkTCP}, nil),
					logger:  logger.NOP(), client: client, dialer: transport, reuse: true,
				}
				delay, err := urltest.URLTest(ctx, "http://probe.test/generate_204", node)
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("physical_connections=%d requests=%d reported_delay=%dms lazy=%v", transport.dials.Load(), handler.requests.Load(), delay, lazy)
				if got := handler.requests.Load(); got != 2 {
					t.Fatalf("HTTP requests = %d, want one warmup and one measured request", got)
				}
				if got := transport.dials.Load(); got != 1 {
					t.Fatalf("physical connections = %d, want the same warm Snell session", got)
				}
			})
		}
	}
}

type urlTestHandler struct {
	N.UDPConnectionHandlerEx
	eofDelay      time.Duration
	requests      atomic.Int32
	afterWarmEOF  func()
	tlsConfig     *tls.Config
	responseDelay time.Duration
}

func (h *urlTestHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	go func() {
		defer onClose(nil)
		if h.tlsConfig != nil {
			tlsConn := tls.Server(conn, h.tlsConfig)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				return
			}
			conn = tlsConn
		}
		request, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			return
		}
		request.Body.Close()
		number := h.requests.Add(1)
		if number == 2 && h.responseDelay != 0 {
			timer := time.NewTimer(h.responseDelay)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-ctx.Done():
				return
			}
		}
		if _, err = io.WriteString(conn, "HTTP/1.1 204 No Content\r\n\r\n"); err != nil {
			return
		}
		io.Copy(io.Discard, conn)
		if number == 1 {
			if h.afterWarmEOF != nil {
				h.afterWarmEOF()
			}
			timer := time.NewTimer(h.eofDelay)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-ctx.Done():
			}
		}
	}()
}

type urlTestTransport struct {
	service     *snellv6.Service
	lazy        bool
	dials       atomic.Int32
	hasDeadline atomic.Bool
	access      sync.Mutex
	connections []net.Conn
}

func (d *urlTestTransport) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.dials.Add(1)
	_, bounded := ctx.Deadline()
	d.hasDeadline.Store(bounded)
	client, server := net.Pipe()
	d.access.Lock()
	d.connections = append(d.connections, client, server)
	d.access.Unlock()
	deadline := time.Now().Add(5 * time.Second)
	client.SetDeadline(deadline)
	server.SetDeadline(deadline)
	go func() {
		d.service.NewConnection(ctx, server, M.Socksaddr{}, func(error) { server.Close() })
		server.Close()
	}()
	if d.lazy {
		return &urlTestLazyConn{Conn: client, ctx: ctx}, nil
	}
	if err := urlTestConnectDelay(ctx); err != nil {
		client.Close()
		return nil, err
	}
	return client, nil
}

func (d *urlTestTransport) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, fmt.Errorf("unexpected UDP dial")
}

func (d *urlTestTransport) Close() {
	d.access.Lock()
	defer d.access.Unlock()
	for _, conn := range d.connections {
		conn.Close()
	}
}

type urlTestLazyConn struct {
	net.Conn
	ctx  context.Context
	once sync.Once
	err  error
}

func (c *urlTestLazyConn) Write(p []byte) (int, error) {
	c.once.Do(func() { c.err = urlTestConnectDelay(c.ctx) })
	if c.err != nil {
		return 0, c.err
	}
	return c.Conn.Write(p)
}

func urlTestConnectDelay(ctx context.Context) error {
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func newURLTestFixture(t *testing.T, handler *urlTestHandler) (*Outbound, *urlTestTransport) {
	t.Helper()
	service, err := snellv6.NewService(snellv6.ServerOptions{
		PSK: []byte("urltest-fixture-key"), Mode: snellv6.ModeDefault, Handler: handler,
	})
	if err != nil {
		t.Fatal(err)
	}
	transport := &urlTestTransport{service: service, lazy: true}
	t.Cleanup(transport.Close)
	client, err := snellv6.NewClient(snellv6.ClientOptions{
		PSK: []byte("urltest-fixture-key"), Mode: snellv6.ModeDefault, Reuse: true,
		Dialer: transport, Server: M.ParseSocksaddr("127.0.0.1:12345"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	return &Outbound{
		Adapter: outbound.NewAdapter(C.TypeSnell, "fixture", []string{N.NetworkTCP}, nil),
		logger:  logger.NOP(), client: client, dialer: transport, reuse: true,
	}, transport
}

func TestURLTestCancelsWaitingWarmSession(t *testing.T) {
	handler := &urlTestHandler{eofDelay: 5 * time.Second}
	node, transport := newURLTestFixture(t, handler)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, err := urltest.URLTest(ctx, "http://probe.test/generate_204", node)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiting for warm EOF returned %v, want deadline exceeded", err)
	}
	if got := transport.dials.Load(); got != 1 {
		t.Fatalf("physical connections = %d, want no redial on timeout", got)
	}
}

func TestURLTestDoesNotRedialClosedWarmSession(t *testing.T) {
	handler := &urlTestHandler{}
	node, transport := newURLTestFixture(t, handler)
	handler.afterWarmEOF = transport.Close
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := urltest.URLTest(ctx, "http://probe.test/generate_204", node)
	if err == nil {
		t.Fatal("closed warm session was accepted")
	}
	if got := transport.dials.Load(); got != 1 {
		t.Fatalf("physical connections = %d, want no redial after loss of the warm session", got)
	}
}

func TestURLTestCloseInterruptsInitialDial(t *testing.T) {
	started := make(chan struct{})
	client, err := snellv6.NewClient(snellv6.ClientOptions{
		PSK: []byte("urltest-fixture-key"), Mode: snellv6.ModeDefault, Reuse: true,
		Dialer: &urlTestBlockingDialer{started: started}, Server: M.ParseSocksaddr("127.0.0.1:12345"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	reserved, err := client.NewURLTestDialer(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer reserved.Close()
	done := make(chan error, 1)
	go func() {
		_, dialErr := reserved.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("probe.test:80"))
		done <- dialErr
	}()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("dial did not start")
	}
	if err := reserved.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("dial returned %v, want cancellation", err)
		}
	case <-ctx.Done():
		t.Fatal("Close did not interrupt the dial")
	}
}

type urlTestBlockingDialer struct {
	N.Dialer
	started chan struct{}
}

func (d *urlTestBlockingDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	close(d.started)
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestURLTestHTTPSPreservesWarmSession(t *testing.T) {
	certificateServer := httptest.NewTLSServer(http.NotFoundHandler())
	link := certificateServer.URL + "/generate_204"
	pool := x509.NewCertPool()
	pool.AddCert(certificateServer.Certificate())
	config := &tls.Config{Certificates: certificateServer.TLS.Certificates}
	certificateServer.Close()
	handler := &urlTestHandler{
		eofDelay: 200 * time.Millisecond, tlsConfig: config, responseDelay: 50 * time.Millisecond,
	}
	node, transport := newURLTestFixture(t, handler)
	ctx := service.ContextWithDefaultRegistry(context.Background())
	service.MustRegister[adapter.CertificateStore](ctx, &urlTestCertificateStore{pool: pool})
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	delay, err := urltest.URLTest(ctx, link, node)
	if err != nil {
		t.Fatal(err)
	}
	if got := transport.dials.Load(); got != 1 {
		t.Fatalf("physical connections = %d, want one for both HTTPS requests", got)
	}
	if got := handler.requests.Load(); got != 2 {
		t.Fatalf("HTTPS requests = %d, want two separate website TLS handshakes and HEAD requests", got)
	}
	if delay < 50 {
		t.Fatalf("reported %dms omitted the measured HTTP response wait", delay)
	}
	t.Logf("HTTPS physical_connections=1 requests=2 reported_delay=%dms (includes a 50ms HTTP response wait)", delay)
}

type urlTestCertificateStore struct {
	adapter.CertificateStore
	pool *x509.CertPool
}

func (s *urlTestCertificateStore) Pool() *x509.CertPool { return s.pool }

func TestURLTestBoundsIndividualPreparation(t *testing.T) {
	handler := &urlTestHandler{eofDelay: 10 * time.Millisecond}
	node, transport := newURLTestFixture(t, handler)
	if _, err := urltest.URLTest(context.Background(), "http://probe.test/generate_204", node); err != nil {
		t.Fatal(err)
	}
	if !transport.hasDeadline.Load() {
		t.Fatal("individual node preparation has no deadline")
	}
}

func TestURLTestWithoutReuseKeepsSingleRequest(t *testing.T) {
	handler := &urlTestHandler{}
	node, transport := newURLTestFixture(t, handler)
	client, err := snellv6.NewClient(snellv6.ClientOptions{
		PSK: []byte("urltest-fixture-key"), Mode: snellv6.ModeDefault, Reuse: false,
		Dialer: transport, Server: M.ParseSocksaddr("127.0.0.1:12345"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	node.client = client
	node.reuse = false
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := urltest.URLTest(ctx, "http://probe.test/generate_204", node); err != nil {
		t.Fatal(err)
	}
	if transport.dials.Load() != 1 || handler.requests.Load() != 1 {
		t.Fatalf("reuse=false changed behavior: dials=%d requests=%d", transport.dials.Load(), handler.requests.Load())
	}
}
