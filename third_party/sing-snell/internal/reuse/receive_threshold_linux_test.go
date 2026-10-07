//go:build linux

package reuse

import (
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func connectedTCP(t testing.TB) (net.Conn, net.Conn) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, _ := listener.Accept()
		accepted <- conn
	}()
	client, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	server := <-accepted
	if server == nil {
		client.Close()
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { client.Close(); server.Close() })
	return client, server
}

type thresholdWrapper struct {
	net.Conn
	replaceable bool
}

func (c thresholdWrapper) ReaderReplaceable() bool { return c.replaceable }
func (c thresholdWrapper) Upstream() any           { return c.Conn }

func TestTCPReceiveThresholdUsesEstablishedSocketWithoutReading(t *testing.T) {
	client, server := connectedTCP(t)
	client.SetDeadline(time.Now().Add(time.Second))
	const payload = "unconsumed payload"
	if _, err := io.WriteString(server, payload); err != nil {
		t.Fatal(err)
	}
	for _, conn := range []net.Conn{client, thresholdWrapper{Conn: client, replaceable: true}} {
		if value, known := TCPReceiveThreshold(conn); !known || value == 0 {
			t.Fatal("established socket or replaceable dialer wrapper had no receive hint")
		}
	}
	buffer := make([]byte, len(payload))
	if _, err := io.ReadFull(client, buffer); err != nil || string(buffer) != payload {
		t.Fatal("receive hint query consumed or altered socket data", err)
	}
	if _, known := TCPReceiveThreshold(thresholdWrapper{Conn: client}); known {
		t.Fatal("non-replaceable transport was unwrapped")
	}
	client.Close()
	if _, known := TCPReceiveThreshold(client); known {
		t.Fatal("closed socket produced a usable hint")
	}
}

func TestTCPReceiveThresholdUnsupportedTransport(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	if _, known := TCPReceiveThreshold(left); known {
		t.Fatal("transport without a TCP descriptor produced a hint")
	}
}

type benchmarkTCPSession struct {
	net.Conn
	state   atomic.Uint32
	measure bool
}

func (s *benchmarkTCPSession) ReuseState() *atomic.Uint32 { return &s.state }
func (s *benchmarkTCPSession) ReceiveThreshold() (uint32, bool) {
	if !s.measure {
		return 0, false
	}
	return TCPReceiveThreshold(s.Conn)
}

func BenchmarkPoolReceiveThreshold(b *testing.B) {
	for _, measure := range []bool{false, true} {
		name := "without_hint"
		if measure {
			name = "tcp_info"
		}
		b.Run(name, func(b *testing.B) {
			p := new(Pool[*benchmarkTCPSession])
			p.Init()
			b.Cleanup(func() { p.Close() })
			for i := 0; i < PoolSize; i++ {
				client, _ := connectedTCP(b)
				p.MoveToPool(&benchmarkTCPSession{Conn: client, measure: measure}, StateReady, false)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				s, found, _ := p.Take()
				if !found {
					b.Fatal("checkout failed")
				}
				s.state.Store(uint32(StateReady))
				if !p.MoveToPool(s, StateReady, false) {
					b.Fatal("return failed")
				}
			}
		})
	}
}
