package vless

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

type flowTestDialer struct {
	N.Dialer
	conn net.Conn
}

func (d *flowTestDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return d.conn, nil
}

type flowTestConn struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

func (c *flowTestConn) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Write(p)
}

func TestXUDPFlowDialCancellationInterruptsInitialRequest(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	conn := &flowTestConn{Conn: clientConn, started: make(chan struct{})}
	client, err := vless.NewClient("b831381d-6324-4d53-ad4f-8cda48b30811", "", logger.NOP())
	require.NoError(t, err)
	h := &Outbound{logger: logger.NOP(), dialer: &flowTestDialer{conn: conn}, client: client}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		packetConn, dialErr := h.dialXUDPFlowPacketConn(ctx, M.SocksaddrFromNetIP(netip.MustParseAddrPort("203.0.113.1:443")))
		if packetConn != nil {
			packetConn.Close()
		}
		done <- dialErr
	}()
	select {
	case <-conn.started:
	case <-time.After(5 * time.Second):
		t.Fatal("XUDP did not start the initial request")
	}
	cancel()
	select {
	case err = <-done:
		require.Error(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("canceling the dial did not interrupt the blocked XUDP request")
	}
}
