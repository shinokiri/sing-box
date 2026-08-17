package snell

import (
	"context"
	"net"
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/udpflow"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	snellprotocol "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/snellv4"
	"github.com/sagernet/sing-snell/snellv6"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.SnellOutboundOptions](registry, C.TypeSnell, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	logger     logger.ContextLogger
	dialer     N.Dialer
	client     snellClient
	serverAddr M.Socksaddr
	flowPort   *udpflow.Port
}

var (
	_ adapter.FlowOutbound            = (*Outbound)(nil)
	_ adapter.InterfaceUpdateListener = (*Outbound)(nil)
)

type snellClient interface {
	snellprotocol.Method
	DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error)
	Reset()
	Close() error
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SnellOutboundOptions) (adapter.Outbound, error) {
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	serverAddr := options.ServerOptions.Build()
	var client snellClient
	switch options.Version {
	case 4:
		var obfsMode snellprotocol.ObfsMode
		obfsMode, err = snellprotocol.ParseObfsMode(options.ObfsOptions.ObfsMode)
		if err != nil {
			return nil, err
		}
		client, err = snellv4.NewClient(snellv4.ClientOptions{
			PSK:      []byte(options.PSK),
			UserKey:  []byte(options.UserKey),
			Reuse:    options.Reuse,
			ObfsMode: obfsMode,
			ObfsHost: options.ObfsOptions.ObfsHost,
			Dialer:   outboundDialer,
			Server:   serverAddr,
		})
	case 6:
		var mode snellv6.Mode
		mode, err = snellv6.ParseMode(options.V6Options.Mode)
		if err != nil {
			return nil, err
		}
		client, err = snellv6.NewClient(snellv6.ClientOptions{
			PSK:     []byte(options.PSK),
			UserKey: []byte(options.UserKey),
			Mode:    mode,
			Reuse:   options.Reuse,
			Dialer:  outboundDialer,
			Server:  serverAddr,
		})
	case 0:
		return nil, E.New("snell: missing version")
	default:
		return nil, E.New("snell: unsupported version: ", options.Version)
	}
	if err != nil {
		return nil, err
	}
	outbound := &Outbound{
		Adapter:    outbound.NewAdapterWithDialerOptions(C.TypeSnell, tag, options.Network.Build(), options.DialerOptions),
		logger:     logger,
		dialer:     outboundDialer,
		client:     client,
		serverAddr: serverAddr,
	}
	if options.UDPFlow {
		outbound.flowPort, err = udpflow.New(udpflow.Options{
			Context: ctx,
			Logger:  logger,
			Name:    "Snell",
			DialPacketConn: func(ctx context.Context, _ M.Socksaddr) (N.NetPacketConn, error) {
				conn, dialErr := outboundDialer.DialContext(ctx, N.NetworkTCP, serverAddr)
				if dialErr != nil {
					return nil, dialErr
				}
				packetConn, dialErr := client.DialPacketConn(conn)
				if dialErr != nil {
					conn.Close()
					return nil, dialErr
				}
				return packetConn, nil
			},
		})
		if err != nil {
			return nil, err
		}
	}
	return outbound, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	networkName := N.NetworkName(network)
	switch networkName {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		return h.client.DialContext(ctx, destination)
	case N.NetworkUDP:
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		conn, err := h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
		if err != nil {
			return nil, err
		}
		packetConn, err := h.client.DialPacketConn(conn)
		if err != nil {
			conn.Close()
			return nil, err
		}
		return bufio.NewBindPacketConn(packetConn, destination), nil
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	conn, err := h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
	if err != nil {
		return nil, err
	}
	packetConn, err := h.client.DialPacketConn(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return packetConn, nil
}

func (h *Outbound) PreMatchFlow(network string, destination netip.Addr) adapter.PreMatchAction {
	if h.flowPort != nil && N.NetworkName(network) == N.NetworkUDP {
		return adapter.PreMatchFlow
	}
	return adapter.PreMatchContinue
}

func (h *Outbound) PortAddresses() (netip.Addr, netip.Addr) {
	if h.flowPort == nil {
		return netip.Addr{}, netip.Addr{}
	}
	return h.flowPort.PortAddresses()
}

func (h *Outbound) PortMTU() uint32 {
	if h.flowPort == nil {
		return 0
	}
	return h.flowPort.PortMTU()
}

func (h *Outbound) PortSelectorRange() (uint16, uint16) {
	if h.flowPort == nil {
		return 0, 0
	}
	return h.flowPort.PortSelectorRange()
}

func (h *Outbound) AttachReturn(returnPath tun.Return) error {
	if h.flowPort == nil {
		return E.New("snell: UDP flow port is disabled")
	}
	return h.flowPort.AttachReturn(returnPath)
}

func (h *Outbound) DetachReturn(returnPath tun.Return) error {
	if h.flowPort == nil {
		return nil
	}
	return h.flowPort.DetachReturn(returnPath)
}

func (h *Outbound) WritePackets(packets [][]byte) error {
	if h.flowPort == nil {
		return E.New("snell: UDP flow port is disabled")
	}
	return h.flowPort.WritePackets(packets)
}

func (h *Outbound) InterfaceUpdated(ctx context.Context) {
	if h.flowPort != nil {
		h.flowPort.Reset()
	}
	h.client.Reset()
}

func (h *Outbound) Close() error {
	var flowErr error
	if h.flowPort != nil {
		flowErr = h.flowPort.Close()
	}
	return E.Errors(flowErr, h.client.Close())
}
