package box_test

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// Exercise config decoding, Fake-IP lookup, resolve rules, and the real router
// entry point used by TUN. The hosts resolver makes this independent of DNS
// servers and a privileged TUN device.
func TestUDPFlowFakeIPRouting(t *testing.T) {
	for _, resolve := range []bool{true, false} {
		t.Run(fmt.Sprintf("resolve=%t", resolve), func(t *testing.T) {
			ctx := include.Context(service.ContextWithDefaultRegistry(context.Background()))
			resolveRule := ""
			if resolve {
				resolveRule = `{"action":"resolve","server":"hosts"},`
			}
			config := fmt.Sprintf(`{
				"log":{"disabled":true},
				"dns":{"servers":[
					{"type":"hosts","tag":"hosts","predefined":{
						"a.test":["203.0.113.1","2001:db8::1"],
						"b.test":["203.0.113.2","2001:db8::2"]}},
					{"type":"fakeip","tag":"fake","inet4_range":"198.18.0.0/15","inet6_range":"fc00::/18"}
				],"final":"hosts"},
				"outbounds":[
					{"type":"snell","tag":"snell","server":"127.0.0.1","server_port":443,"version":6,"psk":"udp-flow-test-key","udp_flow":true},
					{"type":"vless","tag":"vless","server":"127.0.0.1","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","udp_flow":true}
				],
				"route":{"rules":[%s
					{"domain":"a.test","action":"route","outbound":"snell","udp_timeout":"20s"},
					{"action":"route","outbound":"vless","udp_timeout":"20s"}
				]}
			}`, resolveRule)
			var options option.Options
			require.NoError(t, json.UnmarshalContext(ctx, []byte(config), &options))
			instance, err := box.New(box.Options{Context: ctx, Options: options})
			require.NoError(t, err)
			defer instance.Close()
			require.NoError(t, instance.Start())
			store := service.FromContext[adapter.DNSTransportManager](ctx).FakeIP().Store()
			for _, ipv6 := range []bool{false, true} {
				source := netip.MustParseAddrPort("10.0.0.2:50000")
				if ipv6 {
					source = netip.MustParseAddrPort("[fd00::2]:50000")
				}
				for index, domain := range []string{"a.test", "b.test"} {
					fake, err := store.Create(domain, ipv6)
					require.NoError(t, err)
					verdict := adapter.JudgeFlow(instance.Router(), "tun", C.TypeTun, uint8(header.UDPProtocolNumber), source, netip.AddrPortFrom(fake, 443), nil)
					if !resolve {
						require.Equal(t, tun.ActionReject, verdict.Action, "an unresolved Fake-IP must not enter the proxy association")
						continue
					}
					require.Equal(t, tun.ActionFlow, verdict.Action)
					expected := fmt.Sprintf("203.0.113.%d:443", index+1)
					if ipv6 {
						expected = fmt.Sprintf("[2001:db8::%d]:443", index+1)
					}
					require.Equal(t, netip.MustParseAddrPort(expected), verdict.Destination)
					outbound, found := instance.Outbound().Outbound([]string{"snell", "vless"}[index])
					require.True(t, found)
					expectedPort, err := outbound.(adapter.InboundFlowOutbound).FlowPortForInbound("tun")
					require.NoError(t, err)
					require.Same(t, expectedPort, verdict.Port)
					other := adapter.JudgeFlow(instance.Router(), "other-tun", C.TypeTun, uint8(header.UDPProtocolNumber), source, netip.AddrPortFrom(fake, 443), nil)
					require.Equal(t, tun.ActionFlow, other.Action)
					require.NotSame(t, verdict.Port, other.Port)
					require.Equal(t, verdict.Destination, other.Destination)
					require.Equal(t, 20*time.Second, verdict.UDPTimeout)
				}
			}
		})
	}
}
