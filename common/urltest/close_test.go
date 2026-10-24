package urltest

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

type closeTestCertificateStore struct {
	adapter.CertificateStore
	pool *x509.CertPool
}

func (s *closeTestCertificateStore) Pool() *x509.CertPool { return s.pool }

type closeTestDialer struct{ conn *closeTestConn }

func (d closeTestDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return d.conn, nil
}
func (d closeTestDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, fmt.Errorf("unexpected packet dial")
}

type closeTestConn struct {
	net.Conn
	notifyStarted chan struct{}
	allowNotify   chan struct{}
	notifyOnce    sync.Once
	closingTLS    atomic.Bool
	closed        atomic.Bool
}

func (c *closeTestConn) SetWriteDeadline(deadline time.Time) error {
	if !deadline.IsZero() {
		c.closingTLS.Store(true)
	}
	return c.Conn.SetWriteDeadline(deadline)
}

func (c *closeTestConn) Write(p []byte) (int, error) {
	if c.closingTLS.Load() {
		c.notifyOnce.Do(func() { close(c.notifyStarted) })
		<-c.allowNotify
	}
	return c.Conn.Write(p)
}

func (c *closeTestConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

// Force net/http's asynchronous TLS close_notify to overlap URLTest returning.
// Releasing the underlying stream first would let Snell reuse it while TLS is
// still changing deadlines or writing its last alert.
func TestURLTestWaitsForTLSCloseNotify(t *testing.T) {
	// Go TLS may legally skip close_notify if the response arrives while the
	// final request Write is still returning. Exercise that valid branch too,
	// but require a run that reaches asynchronous close_notify. In particular,
	// httptrace.WroteRequest is before the transport flush and cannot be used
	// as a barrier for the TLS writer. No sleep or scheduler timing is needed.
	for attempt := 0; attempt < 16; attempt++ {
		if testURLTestCloseNotify(t) {
			return
		}
	}
	t.Fatal("TLS never entered the close_notify path")
}

func testURLTestCloseNotify(t *testing.T) bool {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	raw, err := net.DialTimeout("tcp", server.Listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	conn := &closeTestConn{Conn: raw, notifyStarted: make(chan struct{}), allowNotify: make(chan struct{})}
	var release sync.Once
	defer release.Do(func() { close(conn.allowNotify) })
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	ctx := service.ContextWithDefaultRegistry(context.Background())
	service.MustRegister[adapter.CertificateStore](ctx, &closeTestCertificateStore{pool: pool})
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { _, err := URLTest(ctx, server.URL, closeTestDialer{conn}); done <- err }()
	select {
	case <-conn.notifyStarted:
	case err := <-done:
		// Close interrupted an in-flight TLS Write and therefore closed the
		// underlying connection without sending close_notify. That is valid.
		if conn.closingTLS.Load() {
			t.Fatal("URLTest returned while TLS cleanup was still running")
		}
		if err != nil || !conn.closed.Load() {
			t.Fatalf("URLTest ended without complete cleanup: error=%v closed=%v", err, conn.closed.Load())
		}
		return false
	case <-ctx.Done():
		t.Fatal("TLS close_notify did not start")
	}

	select {
	case err := <-done:
		t.Fatalf("URLTest returned before TLS cleanup completed: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if conn.closed.Load() {
		t.Fatal("underlying logical connection closed while TLS was still writing")
	}
	release.Do(func() { close(conn.allowNotify) })
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("URLTest did not finish after TLS close_notify")
	}
	if !conn.closed.Load() {
		t.Fatal("URLTest leaked the connection")
	}
	return true
}
