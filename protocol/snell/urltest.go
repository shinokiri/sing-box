package snell

import (
	"context"
	"io"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-snell/snellv6"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var _ adapter.URLTestPreparer = (*Outbound)(nil)

func (h *Outbound) NewURLTestDialer(ctx context.Context) (N.Dialer, io.Closer, error) {
	client, isV6 := h.client.(*snellv6.Client)
	if !h.reuse || !isV6 {
		return h, nil, nil
	}
	reserved, err := client.NewURLTestDialer(ctx)
	if err != nil {
		return nil, nil, err
	}
	return &urlTestDialer{Dialer: reserved, outbound: h}, reserved, nil
}

type urlTestDialer struct {
	N.Dialer
	outbound *Outbound
}

func (d *urlTestDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = d.outbound.Tag()
	metadata.Destination = destination
	d.outbound.logger.InfoContext(ctx, "outbound connection to ", destination)
	return d.Dialer.DialContext(ctx, network, destination)
}
