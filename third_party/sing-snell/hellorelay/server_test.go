package hellorelay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-snell/snellv6"
	M "github.com/sagernet/sing/common/metadata"
)

var testKey = []byte("public-receiver-test-fixture-key")

type memoryConn struct{ bytes.Buffer }

func (*memoryConn) Close() error        { return nil }
func (*memoryConn) LocalAddr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345} }
func (*memoryConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12346}
}
func (*memoryConn) SetDeadline(time.Time) error      { return nil }
func (*memoryConn) SetReadDeadline(time.Time) error  { return nil }
func (*memoryConn) SetWriteDeadline(time.Time) error { return nil }

// Use real Snell encryption and the production carrier writer. The test
// upstream records exact ciphertext; it need not impersonate a Snell server.
func fixture(t *testing.T, size int) (framed, original []byte) {
	t.Helper()
	raw := new(memoryConn)
	client, err := snellv6.NewClient(snellv6.ClientOptions{PSK: testKey, Mode: snellv6.ModeDefault})
	if err != nil {
		t.Fatal(err)
	}
	conn := client.DialEarlyConn(raw, M.ParseSocksaddr("example.com:443"))
	if _, err = conn.Write(bytes.Repeat([]byte{0x71}, size)); err != nil {
		t.Fatal(err)
	}
	original = append([]byte(nil), raw.Bytes()...)
	transport, err := snellv6.NewHelloTransport(testKey)
	if err != nil {
		t.Fatal(err)
	}
	wire := new(memoryConn)
	if _, err = transport.Wrap(wire, "127.0.0.1:12346").Write(original); err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), wire.Bytes()...), original
}

func listenTest(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func startTest(t *testing.T, opts Options) (*Server, string) {
	t.Helper()
	s, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	l, err := s.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(l) }()
	t.Cleanup(func() {
		s.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(2 * time.Second):
			t.Error("Serve did not stop")
		}
		if s.Snapshot().Active != 0 {
			t.Error("active connections after Close")
		}
	})
	return s, l.Addr().String()
}

func dialTest(t *testing.T, address string) *net.TCPConn {
	t.Helper()
	c, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if err = c.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return c.(*net.TCPConn)
}

func result(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not complete")
	}
}

func waitStats(t *testing.T, s *Server, want func(Stats) bool) Stats {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		stats := s.Snapshot()
		if want(stats) {
			return stats
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("stats did not settle: %+v", s.Snapshot())
	return Stats{}
}

func TestReceiverPreservesBothHalfCloseDirections(t *testing.T) {
	framed, original := fixture(t, 2048)
	for _, mode := range []Mode{PassThrough, Decode} {
		for _, serverFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/server_fin_first_%v", mode, serverFirst), func(t *testing.T) {
				up := listenTest(t)
				expected := framed
				if mode == Decode {
					expected = original
				}
				tail := bytes.Repeat([]byte("late upload after FIN\n"), 4096)
				reply := bytes.Repeat([]byte("download\n"), 8192)
				done := make(chan error, 1)
				go func() {
					c, e := up.Accept()
					if e != nil {
						done <- e
						return
					}
					defer c.Close()
					c.SetDeadline(time.Now().Add(3 * time.Second))
					if serverFirst {
						p := make([]byte, len(expected))
						_, e = io.ReadFull(c, p)
						if e == nil && !bytes.Equal(p, expected) {
							e = fmt.Errorf("prefix changed")
						}
						if e == nil {
							_, e = c.Write(reply)
						}
						if e == nil {
							e = c.(*net.TCPConn).CloseWrite()
						}
						if e == nil {
							p, e = io.ReadAll(c)
							if e == nil && !bytes.Equal(p, tail) {
								e = fmt.Errorf("upload after upstream FIN lost")
							}
						}
					} else {
						p, readErr := io.ReadAll(c)
						e = readErr
						if e == nil && !bytes.Equal(p, expected) {
							e = fmt.Errorf("initial stream changed")
						}
						if e == nil {
							_, e = c.Write(reply)
						}
						if e == nil {
							e = c.(*net.TCPConn).CloseWrite()
						}
					}
					done <- e
				}()
				opts := Options{Mode: mode, Upstream: up.Addr().String()}
				if mode == Decode {
					opts.PSK = testKey
				}
				s, address := startTest(t, opts)
				c := dialTest(t, address)
				if _, err := c.Write(framed); err != nil {
					t.Fatal(err)
				}
				if !serverFirst {
					if err := c.CloseWrite(); err != nil {
						t.Fatal(err)
					}
				}
				p, err := io.ReadAll(c)
				if err != nil || !bytes.Equal(p, reply) {
					t.Fatalf("reply incomplete: %d/%d %v", len(p), len(reply), err)
				}
				if serverFirst {
					if _, err = c.Write(tail); err != nil {
						t.Fatal(err)
					}
					if err = c.CloseWrite(); err != nil {
						t.Fatal(err)
					}
				}
				result(t, done)
				waitStats(t, s, func(v Stats) bool { return v.Completed == 1 && v.Active == 0 })
			})
		}
	}
}

func TestReceiverRejectsMalformedAndIncompleteBeforeDial(t *testing.T) {
	framed, _ := fixture(t, 128)
	for _, tc := range []struct {
		name      string
		wire      []byte
		halfClose bool
	}{
		{"oversize_header", []byte{22, 3, 1, 255, 255}, false},
		{"wrong_record", bytes.Repeat([]byte{0}, 86), true},
		{"partial_record", framed[:20], true},
		{"stalled_prefix", framed[:20], false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := New(Options{Mode: Decode, PSK: testKey, Upstream: "127.0.0.1:1", SetupTimeout: 100 * time.Millisecond})
			if err != nil {
				t.Fatal(err)
			}
			var dials atomic.Int32
			s.dial = func(context.Context, string, string) (net.Conn, error) {
				dials.Add(1)
				return nil, fmt.Errorf("unexpected dial")
			}
			l, err := s.Listen("127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- s.Serve(l) }()
			t.Cleanup(func() { s.Close(); result(t, done) })
			c := dialTest(t, l.Addr().String())
			c.Write(tc.wire)
			if tc.halfClose {
				c.CloseWrite()
			}
			_, err = c.Read(make([]byte, 1))
			if err == nil {
				t.Fatal("malformed input remained open")
			}
			if n, ok := err.(net.Error); ok && n.Timeout() {
				t.Fatal("local deadline fired instead of server setup limit")
			}
			waitStats(t, s, func(v Stats) bool { return v.Failed == 1 && v.Active == 0 })
			if dials.Load() != 0 {
				t.Fatal("malformed carrier reached upstream")
			}
		})
	}
}

func TestReceiverAdmissionLimitAndCloseInterruptSetup(t *testing.T) {
	s, address := startTest(t, Options{Mode: PassThrough, Upstream: "127.0.0.1:1", MaxConnections: 1})
	c := dialTest(t, address)
	waitStats(t, s, func(v Stats) bool { return v.Active == 1 })
	extra := dialTest(t, address)
	waitStats(t, s, func(v Stats) bool { return v.Rejected == 1 })
	if _, err := extra.Read(make([]byte, 1)); err == nil {
		t.Fatal("excess connection not closed")
	}
	start := time.Now()
	s.Close()
	if time.Since(start) > time.Second {
		t.Fatal("Close waited for setup timeout")
	}
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("setup socket survived Close")
	}
}

func TestReceiverCloseCancelsPendingDial(t *testing.T) {
	framed, _ := fixture(t, 128)
	s, err := New(Options{Mode: PassThrough, Upstream: "127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	s.dial = func(ctx context.Context, _ string, _ string) (net.Conn, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	l, err := s.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(l) }()
	t.Cleanup(func() { s.Close(); result(t, done) })
	c := dialTest(t, l.Addr().String())
	c.Write(framed)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("dial not reached")
	}
	start := time.Now()
	s.Close()
	if time.Since(start) > time.Second {
		t.Fatal("pending dial did not cancel")
	}
	if s.Snapshot().Active != 0 {
		t.Fatal("pending dial retained session")
	}
}

func TestReceiverSetupTimeoutInterruptsBlockedPrefixWrite(t *testing.T) {
	framed, _ := fixture(t, 128)
	s, err := New(Options{Mode: PassThrough, Upstream: "127.0.0.1:1", SetupTimeout: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	up, peer := net.Pipe()
	defer peer.Close()
	s.dial = func(context.Context, string, string) (net.Conn, error) { return up, nil }
	l, err := s.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(l) }()
	t.Cleanup(func() { s.Close(); result(t, done) })
	c := dialTest(t, l.Addr().String())
	c.Write(framed)
	waitStats(t, s, func(v Stats) bool { return v.Failed == 1 && v.Active == 0 })
}

func TestReceiverCloseInterruptsSteadyStateCopies(t *testing.T) {
	framed, _ := fixture(t, 128)
	up := listenTest(t)
	received := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		c, e := up.Accept()
		if e != nil {
			done <- e
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		p := make([]byte, len(framed))
		_, e = io.ReadFull(c, p)
		close(received)
		if e == nil {
			_, e = io.Copy(io.Discard, c)
		}
		done <- e
	}()
	s, address := startTest(t, Options{Mode: PassThrough, Upstream: up.Addr().String()})
	c := dialTest(t, address)
	c.Write(framed)
	select {
	case <-received:
	case <-time.After(time.Second):
		t.Fatal("not forwarded")
	}
	s.Close()
	result(t, done)
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("steady socket survived Close")
	}
}

func TestReceiverTwoHopIdleSurvivesSetupTimeout(t *testing.T) { runIdleChain(t, 150*time.Millisecond) }

func TestReceiverLongLivedTwoHop(t *testing.T) {
	if os.Getenv("HELLO_LONG_TEST") != "1" {
		t.Skip("explicit 42-second idle test")
	}
	runIdleChain(t, 42*time.Second)
}

func runIdleChain(t *testing.T, idle time.Duration) {
	framed, original := fixture(t, 2048)
	up := listenTest(t)
	done := make(chan error, 1)
	go func() {
		c, e := up.Accept()
		if e != nil {
			done <- e
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(idle + 5*time.Second))
		_, e = io.Copy(c, c)
		if e == nil {
			e = c.(*net.TCPConn).CloseWrite()
		}
		done <- e
	}()
	decode, destination := startTest(t, Options{Mode: Decode, PSK: testKey, Upstream: up.Addr().String(), SetupTimeout: 100 * time.Millisecond})
	pass, address := startTest(t, Options{Mode: PassThrough, Upstream: destination, SetupTimeout: 100 * time.Millisecond})
	c := dialTest(t, address)
	c.SetDeadline(time.Now().Add(idle + 5*time.Second))
	if _, err := c.Write(framed); err != nil {
		t.Fatal(err)
	}
	p := make([]byte, len(original))
	if _, err := io.ReadFull(c, p); err != nil || !bytes.Equal(p, original) {
		t.Fatalf("two-hop decode failed: %v", err)
	}
	time.Sleep(idle)
	// A burst larger than both relay copy buffers must still drain after idle.
	tail := bytes.Repeat([]byte("after idle\n"), 65536)
	written := make(chan error, 1)
	go func() {
		_, e := c.Write(tail)
		if e == nil {
			e = c.CloseWrite()
		}
		written <- e
	}()
	p, err := io.ReadAll(c)
	if err != nil || !bytes.Equal(p, tail) {
		t.Fatalf("idle stream corrupted or cut off: %d/%d %v", len(p), len(tail), err)
	}
	result(t, written)
	result(t, done)
	waitStats(t, pass, func(v Stats) bool { return v.Completed == 1 })
	waitStats(t, decode, func(v Stats) bool { return v.Completed == 1 })
	t.Logf("two-hop stream remained usable after %s idle; %d post-idle bytes verified", idle, len(tail))
}

func TestReceiverCloseBeforeServeAndDoubleClose(t *testing.T) {
	s, err := New(Options{Mode: PassThrough, Upstream: "127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	l := listenTest(t)
	s.Close()
	s.Close()
	if err = s.Serve(l); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	if _, err = l.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatal("unused listener not closed", err)
	}
}
