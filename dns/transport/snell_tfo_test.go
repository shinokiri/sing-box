//go:build linux

package transport

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/database64128/tfo-go/v2"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	boxDNS "github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-snell/snellv6"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	mDNS "github.com/miekg/dns"
)

// This fixture exercises the UDP DNS transport, Snell's real UDP handshake,
// and the production lazy TFO connection. The remote handler receives decoded
// DNS packets, so accepting a TCP socket alone cannot make the test pass.
func TestUDPOverSnellTFODialContext(t *testing.T) {
	for _, fastOpen := range []bool{false, true} {
		t.Run(fmt.Sprintf("tfo_%v", fastOpen), func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			handler := new(snellDNSHandler)
			psk := []byte("dns-context-regression-only")
			server, err := snellv6.NewService(snellv6.ServerOptions{
				PSK: psk, Mode: snellv6.ModeUnshaped, Handler: handler,
			})
			if err != nil {
				t.Fatal(err)
			}
			var accepted atomic.Int32
			go func() {
				for {
					conn, acceptErr := listener.Accept()
					if acceptErr != nil {
						return
					}
					accepted.Add(1)
					_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
					go func() {
						if server.NewConnection(context.Background(), conn, M.SocksaddrFromNet(conn.RemoteAddr()), nil) != nil {
							conn.Close()
						}
					}()
				}
			}()
			client, err := snellv6.NewClient(snellv6.ClientOptions{
				PSK: psk, Mode: snellv6.ModeUnshaped,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			transportDialer := &snellDNSDialer{
				client: client, server: M.SocksaddrFromNet(listener.Addr()),
				tcp: tfo.Dialer{Dialer: net.Dialer{Timeout: time.Second}, DisableTFO: !fastOpen, Fallback: true},
			}
			transport := NewUDPRaw(logger.NOP(), boxDNS.NewTransportAdapter(C.DNSTypeUDP, "real-dns", nil),
				transportDialer, M.ParseSocksaddr("127.0.0.53:53"))
			defer transport.Close()
			for index := 0; index < 3; index++ {
				if index == 2 {
					transport.Reset()
				}
				message := new(mDNS.Msg)
				message.SetQuestion(fmt.Sprintf("query-%d.example.", index), mDNS.TypeA)
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				response, exchangeErr := transport.Exchange(ctx, message)
				cancel()
				if exchangeErr != nil {
					t.Fatalf("query %d: accepted_tcp=%d remote_dns_queries=%d error=%v", index, accepted.Load(), handler.requests.Load(), exchangeErr)
				}
				if response.Id != message.Id || len(response.Answer) != 1 || response.Rcode != mDNS.RcodeSuccess {
					t.Fatalf("invalid DNS response: %v", response)
				}
			}
			if handler.requests.Load() != 3 || accepted.Load() != 2 {
				t.Fatalf("accepted_tcp=%d remote_dns_queries=%d, want 2 connections and 3 queries", accepted.Load(), handler.requests.Load())
			}
			t.Logf("accepted_tcp=%d remote_dns_queries=%d: initial, reuse after request cancellation, and reset succeeded", accepted.Load(), handler.requests.Load())
		})
	}
}

type snellDNSDialer struct {
	client *snellv6.Client
	server M.Socksaddr
	tcp    tfo.Dialer
}

func (d *snellDNSDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	conn, err := dialer.DialSlowContext(&d.tcp, ctx, "tcp", d.server)
	if err != nil {
		return nil, err
	}
	packetConn, err := d.client.DialPacketConn(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return bufio.NewBindPacketConn(packetConn, destination), nil
}

func (d *snellDNSDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, fmt.Errorf("unexpected ListenPacket")
}

type snellDNSHandler struct {
	requests atomic.Int32
}

func (h *snellDNSHandler) NewConnectionEx(_ context.Context, conn net.Conn, _, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	conn.Close()
}

func (h *snellDNSHandler) NewPacketConnectionEx(_ context.Context, conn N.PacketConn, _, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	go func() {
		defer conn.Close()
		packetConn := bufio.NewNetPacketConn(conn)
		buffer := make([]byte, 4096)
		for {
			n, destination, err := packetConn.ReadFrom(buffer)
			if err != nil {
				return
			}
			message := new(mDNS.Msg)
			if message.Unpack(buffer[:n]) != nil || len(message.Question) != 1 || destination.String() != "127.0.0.53:53" {
				return
			}
			h.requests.Add(1)
			response := new(mDNS.Msg)
			response.SetReply(message)
			response.Answer = []mDNS.RR{&mDNS.A{
				Hdr: mDNS.RR_Header{Name: message.Question[0].Name, Rrtype: mDNS.TypeA, Class: mDNS.ClassINET, Ttl: 60},
				A:   net.IPv4(203, 0, 113, 8),
			}}
			raw, packErr := response.Pack()
			if packErr != nil {
				return
			}
			if _, err = packetConn.WriteTo(raw, destination); err != nil {
				return
			}
		}
	}()
}
