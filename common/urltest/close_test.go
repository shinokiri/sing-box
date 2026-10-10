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
}
