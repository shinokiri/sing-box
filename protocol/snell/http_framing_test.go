package snell

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-snell/snellv6"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestURLTestHTTPFramingPreservesPhysicalReuse(t *testing.T) {
	var psk []byte
	for i := 0; i < 100; i++ {
		candidate := []byte(fmt.Sprintf("public HTTP framing fixture %d", i))
		if _, err := snellv6.NewHTTPFraming(candidate); err == nil {
			psk = candidate
			break
		}
	}
	if psk == nil {
		t.Fatal("missing compatible public fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	handler := &urlTestHandler{eofDelay: 20 * time.Millisecond}
	service, err := snellv6.NewService(snellv6.ServerOptions{PSK: psk, HTTPFraming: true, Handler: handler})
	if err != nil {
		t.Fatal(err)
	}
	transport := &urlTestTransport{service: service, lazy: true}
	defer transport.Close()
	client, err := snellv6.NewClient(snellv6.ClientOptions{PSK: psk, HTTPFraming: true, Reuse: true, Dialer: transport, Server: M.ParseSocksaddr("127.0.0.1:12345")})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetKeepIdleConnections(false)
	node := &Outbound{Adapter: outbound.NewAdapter(C.TypeSnell, "fixture", []string{N.NetworkTCP}, nil), logger: logger.NOP(), client: client, dialer: transport, reuse: true}
	if _, err = urltest.URLTest(ctx, "http://probe.test/generate_204", node); err != nil {
		t.Fatal(err)
	}
	if transport.dials.Load() != 1 || handler.requests.Load() != 2 {
		t.Fatalf("physical dials=%d requests=%d", transport.dials.Load(), handler.requests.Load())
	}
}
