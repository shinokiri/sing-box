package udpflow_test

import (
	"context"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/snell"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

type timeoutOutbound struct {
	adapter.Outbound
	elapsed chan time.Duration
}

func (d *timeoutOutbound) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	start := time.Now()
	<-ctx.Done()
	d.elapsed <- time.Since(start)
	return nil, ctx.Err()
}

type timeoutOutboundManager struct {
	adapter.OutboundManager
	outbound adapter.Outbound
}

func (m *timeoutOutboundManager) Outbound(string) (adapter.Outbound, bool) { return m.outbound, true }

// Use the public constructors and a context-bound detour. Virtual time checks
// both shorter and longer user timeouts without waiting 30 seconds per test.
func TestOutboundFlowConnectTimeout(t *testing.T) {
	for _, protocol := range []string{"snell", "vless"} {
		for _, timeout := range []time.Duration{50 * time.Millisecond, 30 * time.Second} {
			t.Run(protocol+"/"+timeout.String(), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					detour := &timeoutOutbound{elapsed: make(chan time.Duration, 1)}
					ctx := service.ContextWith[adapter.OutboundManager](context.Background(), &timeoutOutboundManager{outbound: detour})
					dialOptions := option.DialerOptions{Detour: "blocked"}
					dialOptions.ConnectTimeout = badoption.Duration(timeout)
					server := option.ServerOptions{Server: "127.0.0.1", ServerPort: 443}
					var outbound adapter.Outbound
					var err error
					if protocol == "snell" {
						outbound, err = snell.NewOutbound(ctx, nil, logger.NOP(), "test", option.SnellOutboundOptions{
							Version: 6,
							AbstractSnellOutboundOptions: option.AbstractSnellOutboundOptions{
								DialerOptions: dialOptions, ServerOptions: server, PSK: "udp-flow-test-key", UDPFlow: true,
							},
						})
					} else {
						outbound, err = vless.NewOutbound(ctx, nil, logger.NOP(), "test", option.VLESSOutboundOptions{
							DialerOptions: dialOptions, ServerOptions: server, UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", UDPFlow: true,
						})
					}
					require.NoError(t, err)
					defer common.Close(outbound)
					port := outbound.(tun.Port)
					address, _ := port.PortAddresses()
					packet := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize+1)
					ip := header.IPv4(packet)
					ip.Encode(&header.IPv4Fields{TotalLength: uint16(len(packet)), TTL: 64, Protocol: uint8(header.UDPProtocolNumber), SrcAddr: address, DstAddr: M.ParseSocksaddr("203.0.113.1:443").Addr})
					header.UDP(ip.Payload()).Encode(&header.UDPFields{SrcPort: 50000, DstPort: 443, Length: header.UDPMinimumSize + 1})
					require.NoError(t, port.WritePackets([][]byte{packet}))
					require.Equal(t, timeout, <-detour.elapsed, "flow setup must honor connect_timeout")
				})
			})
		}
	}
}
