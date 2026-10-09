package preconnect

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var testServer = M.ParseSocksaddr("127.0.0.1:1234")

type request struct {
	ctx    context.Context
	result chan net.Conn
}

type fixture struct{ requests chan request }

func (f *fixture) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	r := request{ctx: ctx, result: make(chan net.Conn)}
	select {
	case f.requests <- r:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case conn := <-r.result:
		return conn, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (*fixture) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	panic("unexpected packet dial")
}

func newFixture(t *testing.T) (*Dialer, *fixture) {
	t.Helper()
	f := &fixture{requests: make(chan request, 100)}
	d := New(context.Background(), f, testServer)
	t.Cleanup(func() { d.Close() })
	return d, f
}

func next(t *testing.T, f *fixture) request {
	t.Helper()
	select {
	case r := <-f.requests:
		return r
	case <-time.After(3 * time.Second):
		t.Fatal("dial did not start")
		return request{}
	}
}

func reply(t *testing.T, r request) (net.Conn, net.Conn) {
	t.Helper()
	c, s := net.Pipe()
	t.Cleanup(func() { c.Close(); s.Close() })
	select {
	case r.result <- c:
	case <-time.After(3 * time.Second):
		t.Fatal("dial did not accept result")
	}
	return c, s
}

func demand(d *Dialer) <-chan net.Conn {
	result := make(chan net.Conn, 1)
	go func() { c, _ := d.DialContext(context.Background(), N.NetworkTCP, testServer); result <- c }()
	return result
}

func received(t *testing.T, result <-chan net.Conn) net.Conn {
	t.Helper()
	select {
	case c := <-result:
		if c == nil {
			t.Fatal("demand failed")
		}
		return c
	case <-time.After(3 * time.Second):
		t.Fatal("demand blocked")
		return nil
	}
}

func waitSpare(t *testing.T, d *Dialer) *idleConn {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		d.access.Lock()
		s := d.spare
		d.access.Unlock()
		if s != nil {
			return s
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("spare not prepared")
	return nil
}

func warm(t *testing.T, d *Dialer, f *fixture) (net.Conn, net.Conn) {
	t.Helper()
	first := demand(d)
	reply(t, next(t, f))
	received(t, first).Close()
	c, s := reply(t, next(t, f))
	waitSpare(t, d)
	return c, s
}

func TestDemandUsesSpareWithoutPayloadOrWrapper(t *testing.T) {
	d, f := newFixture(t)
	if len(f.requests) != 0 {
		t.Fatal("eager startup dial")
	}
	c, s := warm(t, d, f)
	// No protocol request or keepalive payload may be sent speculatively.
	s.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	var b [1]byte
	if n, err := s.Read(b[:]); n != 0 || err == nil {
		t.Fatal("unexpected idle data")
	}
	s.SetReadDeadline(time.Time{})
	used := received(t, demand(d))
	if used != c {
		t.Fatal("spare was replaced or active path was wrapped")
	}
	go func() { used.Write([]byte{42}) }()
	if _, err := io.ReadFull(s, b[:]); err != nil || b[0] != 42 {
		t.Fatalf("write: %d %v", b[0], err)
	}
	go func() { s.Write([]byte{99}) }()
	if _, err := io.ReadFull(used, b[:]); err != nil || b[0] != 99 {
		t.Fatalf("read/deadline reset: %d %v", b[0], err)
	}
	used.Close()
}

func TestExpiredSpareClosesWithoutRefill(t *testing.T) {
	d, f := newFixture(t)
	d.idleTimeout = 20 * time.Millisecond
	_, s := warm(t, d, f)
	s.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := s.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("unused socket remained open: %v", err)
	}
	if len(f.requests) != 0 {
		t.Fatal("idle expiry initiated another connection")
	}
	result := demand(d)
	c, _ := reply(t, next(t, f))
	if received(t, result) != c {
		t.Fatal("expired connection used")
	}
}

func TestDeadOrUnexpectedPeerFallsBackBeforeWrite(t *testing.T) {
	for _, unexpected := range []bool{false, true} {
		t.Run(map[bool]string{false: "eof", true: "data"}[unexpected], func(t *testing.T) {
			d, f := newFixture(t)
			_, s := warm(t, d, f)
			idle := waitSpare(t, d)
			if unexpected {
				s.Write([]byte{1})
			} else {
				s.Close()
			}
			<-idle.done
			result := demand(d)
			c, _ := reply(t, next(t, f))
			if received(t, result) != c {
				t.Fatal("dead spare reused")
			}
		})
	}
}

func TestNetworkChangeAndCloseCancelPendingDial(t *testing.T) {
	for _, closeAll := range []bool{false, true} {
		t.Run(map[bool]string{false: "reset", true: "close"}[closeAll], func(t *testing.T) {
			d, f := newFixture(t)
			first := demand(d)
			reply(t, next(t, f))
			received(t, first).Close()
			pending := next(t, f)
			if closeAll {
				d.Close()
			} else {
				d.Reset()
			}
			select {
			case <-pending.ctx.Done():
			case <-time.After(time.Second):
				t.Fatal("background dial not canceled")
			}
			if closeAll {
				if _, err := d.DialContext(context.Background(), N.NetworkTCP, testServer); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("closed dialer: %v", err)
				}
			}
		})
	}
}

func TestDisabledNodeDoesNotPrepareAndResetClosesSpare(t *testing.T) {
	d, f := newFixture(t)
	_, s := warm(t, d, f)
	d.SetEnabled(false)
	s.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := s.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatal("disabled spare remains open")
	}
	first := demand(d)
	reply(t, next(t, f))
	received(t, first).Close()
	if len(f.requests) != 0 {
		t.Fatal("inactive node prepared a connection")
	}
	d.SetEnabled(true)
	warm(t, d, f)
	d.Reset()
	d.access.Lock()
	defer d.access.Unlock()
	if d.spare != nil {
		t.Fatal("network reset retained old spare")
	}
}

func TestParallelMissesKeepOnlyOneSpeculativeDial(t *testing.T) {
	d, f := newFixture(t)
	const count = 16
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, _ := d.DialContext(context.Background(), N.NetworkTCP, testServer)
			if c != nil {
				c.Close()
			}
		}()
	}
	// Every foreground dial is already in flight before any is allowed to
	// complete, so none can consume a speculative connection.
	var pending []request
	for i := 0; i < count; i++ {
		pending = append(pending, next(t, f))
	}
	for _, r := range pending {
		reply(t, r)
	}
	wg.Wait()
	spare := next(t, f)
	if len(f.requests) != 0 {
		t.Fatal("more than one speculative dial")
	}
	reply(t, spare)
	waitSpare(t, d)
}

func TestCanceledCallerDoesNotConsumeSpare(t *testing.T) {
	d, f := newFixture(t)
	c, _ := warm(t, d, f)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := d.DialContext(ctx, N.NetworkTCP, testServer); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if received(t, demand(d)) != c {
		t.Fatal("canceled caller consumed spare")
	}
}

func TestReadClaimRacesWithClose(t *testing.T) {
	for i := 0; i < 100; i++ {
		c, s := net.Pipe()
		idle := newIdleConn(c, time.Second)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			if used := idle.take(); used != nil {
				used.Close()
			}
		}()
		go func() { defer wg.Done(); s.Close() }()
		wg.Wait()
	}
}

func TestSpareHandoffOnTCP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() { conn, _ := listener.Accept(); accepted <- conn }()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	peer := <-accepted
	if peer == nil {
		t.Fatal("accept failed")
	}
	defer peer.Close()
	idle := newIdleConn(conn, time.Second)
	used := idle.take()
	if used != conn {
		t.Fatal("live TCP spare was discarded")
	}
	// A handoff must clear the temporary read deadline before protocol IO.
	go func() { peer.Write([]byte("ok")) }()
	var data [2]byte
	if _, err := io.ReadFull(used, data[:]); err != nil || string(data[:]) != "ok" {
		t.Fatalf("TCP handoff: %q %v", data, err)
	}
}
