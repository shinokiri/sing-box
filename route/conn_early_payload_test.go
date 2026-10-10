package route

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/snellv6"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type earlyPayloadInbound struct {
	net.Conn
	ready         chan struct{}
	once          sync.Once
	readDeadlines atomic.Int32
	noDeadline    bool
}

func (c *earlyPayloadInbound) HandshakeSuccess() error {
	c.once.Do(func() { close(c.ready) })
	return nil
}

func (c *earlyPayloadInbound) SetReadDeadline(deadline time.Time) error {
	if !deadline.IsZero() {
		c.readDeadlines.Add(1)
		if c.noDeadline {
			return os.ErrInvalid
		}
	}
	return c.Conn.SetReadDeadline(deadline)
}

type earlyPayloadDialer struct {
	N.Dialer
	dial func(context.Context, M.Socksaddr) (net.Conn, error)
}

func (d earlyPayloadDialer) DialContext(ctx context.Context, _ string, destination M.Socksaddr) (net.Conn, error) {
	return d.dial(ctx, destination)
}

type earlyPayloadDecoded struct {
	net.Conn
	reader io.Reader
}

func (c earlyPayloadDecoded) Read(p []byte) (int, error) { return c.reader.Read(p) }

type earlyPayloadDisabled struct{ net.Conn }

func (c earlyPayloadDisabled) PreferEarlyPayload() bool { return false }
func (c earlyPayloadDisabled) Upstream() any            { return c.Conn }

type earlyPayloadHandler struct {
	payload     []byte
	serverFirst bool
	done        chan error
}

func (h earlyPayloadHandler) NewConnectionEx(_ context.Context, conn net.Conn, _, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	go func() {
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		var err error
		if !h.serverFirst {
			got := make([]byte, len(h.payload))
			_, err = io.ReadFull(conn, got)
			if err == nil && !bytes.Equal(got, h.payload) {
				err = fmt.Errorf("application payload changed")
			}
		}
		if err == nil {
			_, err = conn.Write(h.payload)
		}
		h.done <- err
		if onClose != nil {
			onClose(err)
		}
	}()
}

func (h earlyPayloadHandler) NewPacketConnectionEx(_ context.Context, conn N.PacketConn, _, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	conn.Close()
	if onClose != nil {
		onClose(fmt.Errorf("unexpected packet connection"))
	}
}

// Exercise ConnectionManager, the real Snell client/carrier and Snell service.
// Calling client.Write directly skips the route-layer empty write that caused
// installed HTTPS connections to spend their SYN on only the proxy header.
func TestHelloRouteEarlyPayload(t *testing.T) {
	for _, test := range []struct {
		name                                                string
		port                                                uint16
		protocol                                            string
		reuse, cached, serverFirst, disableHint, noDeadline bool
		wantEarly                                           bool
		wantReadDeadline                                    bool
	}{
		{name: "uncached_https", port: 443, wantEarly: true, wantReadDeadline: true},
		{name: "uncached_https_reuse", port: 443, reuse: true, wantEarly: true, wantReadDeadline: true},
		{name: "cached_https", port: 443, cached: true, wantEarly: true},
		{name: "sniffed_tls_custom_port", port: 8443, protocol: C.ProtocolTLS, wantEarly: true, wantReadDeadline: true},
		{name: "http", port: 80, wantEarly: true, wantReadDeadline: true},
		{name: "ssh_custom_port", port: 61667, serverFirst: true},
		{name: "smtp", port: 25, serverFirst: true},
		{name: "ordinary_transport", port: 443, disableHint: true},
		{name: "server_first_on_web_port_falls_back", port: 443, serverFirst: true, wantReadDeadline: true},
		{name: "unsupported_deadline_falls_back", port: 443, noDeadline: true, wantReadDeadline: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			psk := []byte("public-route-early-payload-test-key")
			payload := bytes.Repeat([]byte{0x61}, 64)
			serverDone := make(chan error, 1)
			service, err := snellv6.NewService(snellv6.ServerOptions{PSK: psk, Handler: earlyPayloadHandler{payload: payload, serverFirst: test.serverFirst, done: serverDone}})
			if err != nil {
				t.Fatal(err)
			}
			transport, err := snellv6.NewHelloTransportWithOptions(psk, snellv6.HelloTransportOptions{InitialSYNDataLimit: 1200})
			if err != nil {
				t.Fatal(err)
			}
			frames := make(chan snellv6.HelloFrameInfo, 1)
			transport.OnFirstFrame = func(info snellv6.HelloFrameInfo) { frames <- info }
			clientWire, serverWire := net.Pipe()
			t.Cleanup(func() { clientWire.Close(); serverWire.Close() })
			serverExit := make(chan struct{})
			go func() {
				defer close(serverExit)
				_ = serverWire.SetDeadline(time.Now().Add(3 * time.Second))
				prefix, decodeErr := transport.DecodeHello(serverWire)
				if decodeErr != nil {
					serverDone <- decodeErr
					return
				}
				decoded := earlyPayloadDecoded{Conn: serverWire, reader: io.MultiReader(bytes.NewReader(prefix), serverWire)}
				_ = service.NewConnection(context.Background(), decoded, M.Socksaddr{}, func(error) { serverWire.Close() })
			}()
			base := earlyPayloadDialer{dial: func(context.Context, M.Socksaddr) (net.Conn, error) { return clientWire, nil }}
			wrapped := transport.WrapDialer(base)
			if test.disableHint {
				upstream := wrapped
				wrapped = earlyPayloadDialer{dial: func(ctx context.Context, dest M.Socksaddr) (net.Conn, error) {
					conn, dialErr := upstream.DialContext(ctx, N.NetworkTCP, dest)
					return earlyPayloadDisabled{conn}, dialErr
				}}
			}
			client, err := snellv6.NewClient(snellv6.ClientOptions{PSK: psk, Reuse: test.reuse, Dialer: wrapped, Server: M.ParseSocksaddr("127.0.0.1:10000")})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { client.Close() })
			outbound := earlyPayloadDialer{dial: client.DialContext}
			app, inboundPipe := net.Pipe()
			t.Cleanup(func() { app.Close(); inboundPipe.Close() })
			_ = app.SetDeadline(time.Now().Add(3 * time.Second))
			inbound := &earlyPayloadInbound{Conn: inboundPipe, ready: make(chan struct{}), noDeadline: test.noDeadline}
			var source net.Conn = inbound
			if test.cached {
				source = bufio.NewCachedConn(source, buf.As(append([]byte(nil), payload...)))
			}
			metadata := adapter.InboundContext{Destination: M.ParseSocksaddr(fmt.Sprintf("example.test:%d", test.port)), Protocol: test.protocol}
			manager := NewConnectionManager(logger.NOP())
			routeStarted := make(chan struct{})
			go func() {
				manager.NewConnection(context.Background(), outbound, source, metadata, nil)
				close(routeStarted)
			}()
			select {
			case <-inbound.ready:
			case <-time.After(3 * time.Second):
				t.Fatal("local handshake was not reported")
			}
			if !test.serverFirst && !test.cached {
				if _, err = app.Write(payload); err != nil {
					t.Fatal(err)
				}
			}
			got := make([]byte, len(payload))
			if _, err = io.ReadFull(app, got); err != nil || !bytes.Equal(got, payload) {
				t.Fatal("application exchange failed", err)
			}
			if err = <-serverDone; err != nil {
				t.Fatal(err)
			}
			var frame snellv6.HelloFrameInfo
			select {
			case frame = <-frames:
			case <-time.After(3 * time.Second):
				t.Fatal("no first physical write")
			}
			request := snell.Request{Command: snell.CommandConnectV2, Destination: metadata.Destination}
			wantWire := 141 + request.Len()
			if test.wantEarly {
				wantWire += len(payload)
			}
			if frame.WireBytes != wantWire {
				t.Errorf("first carrier has %d bytes, want %d; application data missed the first flight", frame.WireBytes, wantWire)
			}
			if (inbound.readDeadlines.Load() > 0) != test.wantReadDeadline {
				t.Errorf("unexpected first-payload wait: %d deadline calls", inbound.readDeadlines.Load())
			}
			app.Close()
			inboundPipe.Close()
			client.Close()
			clientWire.Close()
			serverWire.Close()
			select {
			case <-routeStarted:
			case <-time.After(3 * time.Second):
				t.Fatal("route setup did not finish")
			}
			select {
			case <-serverExit:
			case <-time.After(3 * time.Second):
				t.Fatal("server did not finish")
			}
		})
	}
}
