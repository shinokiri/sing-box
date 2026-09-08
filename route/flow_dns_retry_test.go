package route

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	mDNS "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

type retryFlowDNS struct {
	adapter.DNSRouter
	lookups  atomic.Int32
	address  netip.Addr
	failures int32
}

func (d *retryFlowDNS) Lookup(context.Context, string, adapter.DNSQueryOptions) ([]netip.Addr, error) {
	if d.lookups.Add(1) <= d.failures {
		return nil, context.DeadlineExceeded
	}
	return []netip.Addr{d.address}, nil
}

func (*retryFlowDNS) LookupReverseMapping(netip.Addr) (string, bool) { return "", false }
func (*retryFlowDNS) ExchangeAsync(_ context.Context, query *mDNS.Msg, _ adapter.DNSQueryOptions, callback func(*mDNS.Msg, error)) {
	response := new(mDNS.Msg)
	response.SetReply(query)
	callback(response, nil) // Same synchronous callback contract as a cache hit.
}

type blockingFlowWriteback struct {
	packets chan []byte
	entered chan struct{}
	resume  chan struct{}
	once    sync.Once
}

func (*blockingFlowWriteback) ReturnHeadroom() int { return 0 }
func (w *blockingFlowWriteback) WriteReturnPackets(packets [][]byte) error {
	if w.entered != nil {
		w.once.Do(func() { close(w.entered) })
		<-w.resume
	}
	for _, p := range packets {
		w.packets <- append([]byte(nil), p...)
	}
	return nil
}

type dnsFlowHandler struct{ routeFlowHandler }

func (h dnsFlowHandler) NewDNSPacket(payload []byte, source, destination M.Socksaddr, writer N.PacketWriter) {
	h.router.HijackDNSPacket(context.Background(), payload, writer, adapter.InboundContext{
		Inbound: "tun", InboundType: C.TypeTun, Network: N.NetworkUDP,
		Source: source, Destination: destination,
	})
}

func addFlowRules(t *testing.T, router *Router, configs ...string) {
	t.Helper()
	for _, config := range configs {
		var options option.Rule
		require.NoError(t, json.Unmarshal([]byte(config), &options))
		rule, err := R.NewRule(router.ctx, logger.NOP(), options, false)
		require.NoError(t, err)
		router.rules = append(router.rules, rule)
	}
}

// Active retries must neither hammer a failing resolver nor renew its failure
// forever. Exercise real resolve/route rules and both IP families with fake time.
func TestUDPFlowRetriesTransientDNSFailure(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		name := "IPv4"
		if ipv6 {
			name = "IPv6"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx := context.Background()
				source, fake, real, portAddress := netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("127.0.0.1")
				if ipv6 {
					source, fake, real, portAddress = netip.MustParseAddr("fd00::2"), netip.MustParseAddr("fc00::1"), netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("fd01::1")
				}
				dns := &retryFlowDNS{address: real, failures: 2}
				port := &routeFlowPort{tag: "fast", address: portAddress, sent: make(chan []byte, 4)}
				router := &Router{ctx: ctx, logger: logger.NOP(), dns: dns,
					dnsTransport: flowDNSManager{fake: flowFakeTransport{store: flowFakeStore{address: fake}}},
					outbound:     flowOutboundManager{ports: map[string]*routeFlowPort{"fast": port}},
				}
				addFlowRules(t, router, `{"action":"resolve"}`, `{"action":"route","outbound":"fast"}`)
				w := &blockingFlowWriteback{packets: make(chan []byte, 8)}
				d := tun.NewForwardDispatcher(routeFlowHandler{router: router}, w, logger.NOP(), 5*time.Minute, time.Minute)
				d.EnableAsyncFlow(ctx, func([]byte) { t.Error("unexpected ordinary fallback") })
				defer d.Close()
				for attempt := int32(1); attempt <= dns.failures; attempt++ {
					d.Dispatch(dnsTestPacket(source, fake, "lookup"))
					d.Flush()
					flowReceive(t, w.packets)
					synctest.Wait()
					for range 10 {
						time.Sleep(100 * time.Millisecond)
						d.Dispatch(dnsTestPacket(source, fake, "retry"))
						d.Flush()
						flowReceive(t, w.packets)
					}
					require.Equal(t, attempt, dns.lookups.Load(), "retries within the fixed deadline share the failed lookup")
					time.Sleep(time.Nanosecond)
				}
				d.Dispatch(dnsTestPacket(source, fake, "recovered"))
				raw := flowReceive(t, port.sent)
				var ip header.Network = header.IPv4(raw)
				if ipv6 {
					ip = header.IPv6(raw)
				}
				require.Equal(t, real, ip.DestinationAddr())
				require.Equal(t, "recovered", string(header.UDP(ip.Payload()).Payload()))
				synctest.Wait()
				require.Equal(t, int32(3), dns.lookups.Load())
			})
		})
	}
}

// Exercise the real Router.HijackDNSPacket and synchronous cached-response path.
func TestUDPFlowCachedDNSWritebackDoesNotBlockEstablishedFlow(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	source, fast := netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("203.0.113.1")
	port := &routeFlowPort{tag: "fast", address: netip.MustParseAddr("127.0.0.1"), sent: make(chan []byte, 4)}
	router := &Router{ctx: ctx, logger: logger.NOP(), dns: &retryFlowDNS{},
		dnsTransport: flowDNSManager{}, outbound: flowOutboundManager{ports: map[string]*routeFlowPort{"fast": port}},
	}
	addFlowRules(t, router, `{"port":53,"action":"hijack-dns"}`, `{"action":"route","outbound":"fast"}`)
	w := &blockingFlowWriteback{packets: make(chan []byte, 8), entered: make(chan struct{}), resume: make(chan struct{})}
	release := sync.OnceFunc(func() { close(w.resume) })
	d := tun.NewForwardDispatcher(dnsFlowHandler{routeFlowHandler{router: router}}, w, logger.NOP(), time.Minute, time.Minute)
	d.EnableAsyncFlow(ctx, func([]byte) { t.Error("unexpected ordinary fallback") })
	defer func() { release(); d.Close() }()
	d.Dispatch(dnsTestPacket(source, fast, "establish"))
	flowReceive(t, port.sent)
	query := new(mDNS.Msg)
	query.SetQuestion("cached.test.", mDNS.TypeA)
	payload, err := query.Pack()
	require.NoError(t, err)
	raw := dnsTestPacket(source, netip.MustParseAddr("192.0.2.53"), string(payload))
	header.UDP(header.IPv4(raw).Payload()).SetDestinationPort(53)
	d.Dispatch(raw)
	flowReceive(t, w.entered)
	done := make(chan struct{})
	go func() {
		d.Dispatch(dnsTestPacket(source, fast, "fast packet"))
		d.Flush()
		close(done)
	}()
	flowReceive(t, done)
	forwarded := flowReceive(t, port.sent) // Must arrive before the DNS write resumes.
	require.Equal(t, "fast packet", string(header.UDP(header.IPv4(forwarded).Payload()).Payload()))
	release()
	response := flowReceive(t, w.packets)
	var answer mDNS.Msg
	require.NoError(t, answer.Unpack(header.UDP(header.IPv4(response).Payload()).Payload()))
	require.Equal(t, query.Id, answer.Id)
	require.True(t, answer.Response)
}
