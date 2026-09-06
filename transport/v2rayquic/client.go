//go:build with_quic

package v2rayquic

import (
	"context"
	"net"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-quic"
	"github.com/sagernet/sing/common"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/sync/semaphore"
)

var _ adapter.V2RayClientTransport = (*Client)(nil)

type Client struct {
	ctx        context.Context
	dialer     N.Dialer
	serverAddr M.Socksaddr
	tlsConfig  tls.Config
	quicConfig *quic.Config
	connAccess *semaphore.Weighted
	conn       common.TypedValue[*quic.Conn]
	rawConn    net.Conn
}

func NewClient(ctx context.Context, dialer N.Dialer, serverAddr M.Socksaddr, options option.V2RayQUICOptions, tlsConfig tls.Config) (adapter.V2RayClientTransport, error) {
	quicConfig := &quic.Config{
		DisablePathMTUDiscovery: !C.IsLinux && !C.IsWindows,
	}
	if len(tlsConfig.NextProtos()) == 0 {
		tlsConfig.SetNextProtos([]string{http3.NextProtoH3})
	}
	return &Client{
		ctx:        ctx,
		dialer:     dialer,
		serverAddr: serverAddr,
		tlsConfig:  tlsConfig,
		quicConfig: quicConfig,
		connAccess: semaphore.NewWeighted(1),
	}, nil
}

func (c *Client) offer(ctx context.Context) (*quic.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	conn := c.conn.Load()
	if conn != nil && !common.Done(conn.Context()) {
		return conn, nil
	}
	// Waiting for another selector's handshake must honor this caller's
	// cancellation just as dialing a new connection does.
	if err := c.connAccess.Acquire(ctx, 1); err != nil {
		return nil, err
	}
	defer c.connAccess.Release(1)
	conn = c.conn.Load()
	if conn != nil && !common.Done(conn.Context()) {
		return conn, nil
	}
	conn, err := c.offerNew(ctx)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (c *Client) offerNew(ctx context.Context) (*quic.Conn, error) {
	udpConn, err := c.dialer.DialContext(ctx, "udp", c.serverAddr)
	if err != nil {
		return nil, err
	}
	quicConn, err := qtls.Dial(ctx, udpConn, c.tlsConfig, c.quicConfig)
	if err != nil {
		udpConn.Close()
		return nil, err
	}
	// quic-go does not take ownership of the conn passed to Dial:
	// when the connection ends it only stops reading.
	go func() {
		<-quicConn.Context().Done()
		udpConn.Close()
	}()
	c.conn.Store(quicConn)
	c.rawConn = udpConn
	return quicConn, nil
}

func (c *Client) DialContext(ctx context.Context) (net.Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	stopCancel := context.AfterFunc(c.ctx, cancel)
	defer stopCancel()
	defer cancel()
	// QUIC detaches its established connection from the handshake context;
	// canceling this call must not terminate other streams using it.
	conn, err := c.offer(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := conn.OpenStream()
	if err != nil {
		return nil, err
	}
	return &StreamWrapper{Conn: conn, Stream: stream}, nil
}

func (c *Client) Close() error {
	if err := c.connAccess.Acquire(context.Background(), 1); err != nil {
		return err
	}
	defer c.connAccess.Release(1)
	conn := c.conn.Swap(nil)
	if conn != nil {
		conn.CloseWithError(0, "")
	}
	if c.rawConn != nil {
		c.rawConn.Close()
	}
	c.rawConn = nil
	return nil
}
