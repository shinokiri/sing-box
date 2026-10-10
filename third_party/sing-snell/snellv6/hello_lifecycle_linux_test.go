//go:build linux

package snellv6

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type helloHeldDialer struct {
	N.Dialer
	entered chan struct{}
	release chan struct{}
}

func (d *helloHeldDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	conn, err := d.Dialer.DialContext(ctx, network, destination)
	if err != nil {
		return nil, err
	}
	close(d.entered)
	select {
	case <-d.release:
		return conn, nil
	case <-ctx.Done():
		conn.Close()
		return nil, ctx.Err()
	}
}

// A network update can occur after the upstream socket was opened but before
// DialContext returns. The old socket must not seed a new network's SYN budget.
func TestHelloResetDuringDialDoesNotLearnOldPath(t *testing.T) {
	endpoint, _ := newHelloTestServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	transport, err := NewHelloTransport(helloTestPSK)
	if err != nil {
		t.Fatal(err)
	}
	frames := make(chan HelloFrameInfo, 2)
	transport.OnFirstFrame = func(info HelloFrameInfo) { frames <- info }
	upstream := &helloHeldDialer{
		Dialer:  &helloTestDialer{endpoint: endpoint},
		entered: make(chan struct{}), release: make(chan struct{}),
	}
	unblock := sync.OnceFunc(func() { close(upstream.release) })
	defer unblock()
	type result struct {
		conn net.Conn
		err  error
	}
	completed := make(chan result, 1)
	go func() {
		conn, err := transport.WrapDialer(upstream).DialContext(ctx, "tcp", M.ParseSocksaddr(endpoint))
		completed <- result{conn, err}
	}()
	select {
	case <-upstream.entered:
	case <-ctx.Done():
		t.Fatal("upstream dial did not enter")
	}
	transport.Reset()
	unblock()
	var raw net.Conn
	select {
	case r := <-completed:
		if r.err != nil {
			t.Fatal(r.err)
		}
		raw = r.conn
	case <-ctx.Done():
		t.Fatal("upstream dial did not finish")
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(2 * time.Second))
	client, err := NewClient(ClientOptions{PSK: helloTestPSK})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	old := client.DialEarlyConn(raw, M.ParseSocksaddr("example.test:443"))
	defer old.Close()
	want := []byte("old network request completes after reset")
	if _, err = old.Write(want); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err = io.ReadFull(old, got); err != nil || !bytes.Equal(got, want) {
		t.Fatal("old connection exchange", err)
	}
	<-frames

	// Model the next deferred socket before it has its own MSS observation.
	// Its emitted first frame, not an internal generation counter, is checked.
	address, err := net.ResolveTCPAddr("tcp", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	pending := transport.Wrap(helloAddressMemoryConn{new(helloMemoryConn), address}, endpoint)
	defer pending.Close()
	next := client.DialEarlyConn(pending, M.ParseSocksaddr("example.test:443"))
	defer next.Close()
	if _, err = next.Write(want); err != nil {
		t.Fatal(err)
	}
	info := <-frames
	if info.BudgetSource != "cold_estimate" || info.Budget != helloColdBudget {
		t.Fatalf("new network inherited old-path observation: %+v", info)
	}
}
