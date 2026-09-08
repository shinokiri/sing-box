package route

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/logger"
	"github.com/stretchr/testify/require"
)

type flowDNS struct {
	adapter.DNSRouter
	started, resume chan struct{}
	address         netip.Addr
	calls           atomic.Int32
	finished        chan error
}

func (d *flowDNS) Lookup(ctx context.Context, _ string, _ adapter.DNSQueryOptions) ([]netip.Addr, error) {
	d.calls.Add(1)
	d.started <- struct{}{}
	select {
	case <-d.resume:
		d.finished <- nil
		return []netip.Addr{d.address}, nil
	case <-ctx.Done():
		d.finished <- ctx.Err()
		return nil, ctx.Err()
	}
}

func (*flowDNS) LookupReverseMapping(netip.Addr) (string, bool) { return "", false }

type flowFakeStore struct {
	adapter.FakeIPStore
	address netip.Addr
}

func (s flowFakeStore) Contains(address netip.Addr) bool { return address == s.address }
func (flowFakeStore) Lookup(netip.Addr) (string, bool)   { return "cold.test", true }

type flowFakeTransport struct {
	adapter.FakeIPTransport
	store adapter.FakeIPStore
}

func (t flowFakeTransport) Store() adapter.FakeIPStore { return t.store }

type flowDNSManager struct {
	adapter.DNSTransportManager
	fake adapter.FakeIPTransport
}

func (m flowDNSManager) FakeIP() adapter.FakeIPTransport { return m.fake }

type routeFlowPort struct {
	adapter.Outbound
	tag     string
	address netip.Addr
	sent    chan []byte
}

func (*routeFlowPort) Type() string      { return "test" }
func (p *routeFlowPort) Tag() string     { return p.tag }
func (*routeFlowPort) Network() []string { return []string{"udp"} }
func (*routeFlowPort) PreMatchFlow(string, netip.Addr) adapter.PreMatchAction {
	return adapter.PreMatchFlow
}
func (p *routeFlowPort) PortAddresses() (netip.Addr, netip.Addr) {
	if p.address.Is4() {
		return p.address, netip.Addr{}
	}
	return netip.Addr{}, p.address
}
func (*routeFlowPort) PortMTU() uint32               { return 0 }
func (*routeFlowPort) AttachReturn(tun.Return) error { return nil }
func (*routeFlowPort) DetachReturn(tun.Return) error { return nil }
func (p *routeFlowPort) WritePackets(packets [][]byte) error {
	for _, packet := range packets {
		p.sent <- append([]byte(nil), packet...)
	}
	return nil
}

type flowOutboundManager struct {
	adapter.OutboundManager
	ports map[string]*routeFlowPort
}

func (m flowOutboundManager) Default() adapter.Outbound { return m.ports["fast"] }
func (m flowOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	port, loaded := m.ports[tag]
	return port, loaded
}

type routeFlowHandler struct {
	tun.Handler
	router *Router
}

func (h routeFlowHandler) JudgeFlowContext(ctx context.Context, network uint8, source, destination netip.AddrPort, payload []byte) tun.FlowVerdict {
	return adapter.JudgeFlowContext(ctx, h.router, "tun", C.TypeTun, network, source, destination, payload)
}

type flowWriteback struct{ tun.ForwardWriteback }

func (flowWriteback) ReturnHeadroom() int { return 0 }

func dnsTestPacket(source, destination netip.Addr, payload string) []byte {
	var ip header.Network
	if source.Is4() {
		h := header.IPv4(make([]byte, 28+len(payload)))
		h.Encode(&header.IPv4Fields{TotalLength: uint16(len(h)), TTL: 64, Protocol: uint8(header.UDPProtocolNumber), SrcAddr: source, DstAddr: destination})
		ip = h
	} else {
		h := header.IPv6(make([]byte, 48+len(payload)))
		h.Encode(&header.IPv6Fields{PayloadLength: uint16(8 + len(payload)), HopLimit: 64, TransportProtocol: header.UDPProtocolNumber, SrcAddr: source, DstAddr: destination})
		ip = h
	}
	udp := header.UDP(ip.Payload())
	udp.Encode(&header.UDPFields{SrcPort: 50000, DstPort: 443, Length: uint16(8 + len(payload))})
	copy(udp.Payload(), payload)
	if h, ok := ip.(header.IPv4); ok {
		return h
	}
	return ip.(header.IPv6)
}

func flowReceive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for flow event")
		var zero T
		return zero
	}
}

func TestUDPFlowColdDNSDoesNotBlockEstablishedFlow(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		name := "IPv4"
		if ipv6 {
			name = "IPv6"
		}
		t.Run(name, func(t *testing.T) {
			source, fake, real, fast := netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("192.0.2.2")
			portA, portB := netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2")
			if ipv6 {
				source, fake, real, fast = netip.MustParseAddr("fd00::2"), netip.MustParseAddr("fc00::1"), netip.MustParseAddr("2001:db8:1::1"), netip.MustParseAddr("2001:db8:2::1")
				portA, portB = netip.MustParseAddr("fd01::1"), netip.MustParseAddr("fd01::2")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			dns := &flowDNS{started: make(chan struct{}, 4), resume: make(chan struct{}), finished: make(chan error, 4), address: real}
			coldPort := &routeFlowPort{tag: "resolved", address: portA, sent: make(chan []byte, 4)}
			fastPort := &routeFlowPort{tag: "fast", address: portB, sent: make(chan []byte, 4)}
			router := &Router{ctx: ctx, logger: logger.NOP(), dns: dns, dnsTransport: flowDNSManager{fake: flowFakeTransport{store: flowFakeStore{address: fake}}}, outbound: flowOutboundManager{ports: map[string]*routeFlowPort{"resolved": coldPort, "fast": fastPort}}}
			// Real resolve, route-options and IP-CIDR rules must run in order.
			for _, config := range []string{
				`{"action":"resolve"}`,
				`{"action":"route-options","udp_timeout":"20s"}`,
				`{"ip_cidr":["203.0.113.0/24","2001:db8:1::/48"],"action":"route","outbound":"resolved"}`,
				`{"action":"route","outbound":"fast"}`,
			} {
				var options option.Rule
				require.NoError(t, json.Unmarshal([]byte(config), &options))
				rule, err := R.NewRule(ctx, logger.NOP(), options, false)
				require.NoError(t, err)
				router.rules = append(router.rules, rule)
			}
			dispatcher := tun.NewForwardDispatcher(routeFlowHandler{router: router}, flowWriteback{}, logger.NOP(), time.Minute, time.Minute)
			dispatcher.EnableAsyncFlow(ctx, func([]byte) { t.Error("unexpected ordinary-stack fallback") })
			defer dispatcher.Close()
			require.True(t, dispatcher.Dispatch(dnsTestPacket(source, fast, "establish")))
			flowReceive(t, fastPort.sent)
			for _, payload := range []string{"first", "second"} {
				packet := dnsTestPacket(source, fake, payload)
				require.True(t, dispatcher.Dispatch(packet))
				clear(packet)
			}
			flowReceive(t, dns.started)
			require.True(t, dispatcher.Dispatch(dnsTestPacket(source, fast, "still moving")))
			dispatcher.Flush()
			flowReceive(t, fastPort.sent) // Must arrive before DNS is allowed to finish.
			require.Equal(t, int32(1), dns.calls.Load(), "one lookup for the pending tuple")
			close(dns.resume)
			for _, payload := range []string{"first", "second"} {
				raw := flowReceive(t, coldPort.sent)
				var ip header.Network = header.IPv4(raw)
				if ipv6 {
					ip = header.IPv6(raw)
				}
				require.Equal(t, real, ip.DestinationAddr())
				require.Equal(t, payload, string(header.UDP(ip.Payload()).Payload()))
			}
		})
	}
}

func TestUDPFlowCloseCancelsRoutingDNS(t *testing.T) {
	ctx := context.Background()
	dns := &flowDNS{started: make(chan struct{}, 1), resume: make(chan struct{}), finished: make(chan error, 1)}
	fake := netip.MustParseAddr("198.18.0.1")
	router := &Router{ctx: ctx, logger: logger.NOP(), dns: dns, dnsTransport: flowDNSManager{fake: flowFakeTransport{store: flowFakeStore{address: fake}}}}
	var options option.Rule
	require.NoError(t, json.Unmarshal([]byte(`{"action":"resolve"}`), &options))
	rule, err := R.NewRule(ctx, logger.NOP(), options, false)
	require.NoError(t, err)
	router.rules = []adapter.Rule{rule}
	dispatcher := tun.NewForwardDispatcher(routeFlowHandler{router: router}, flowWriteback{}, logger.NOP(), time.Minute, time.Minute)
	dispatcher.EnableAsyncFlow(ctx, func([]byte) { t.Error("canceled DNS must not route a packet") })
	defer dispatcher.Close()
	require.True(t, dispatcher.Dispatch(dnsTestPacket(netip.MustParseAddr("10.0.0.2"), fake, "query")))
	flowReceive(t, dns.started)
	dispatcher.Close()
	require.ErrorIs(t, flowReceive(t, dns.finished), context.Canceled)
}
