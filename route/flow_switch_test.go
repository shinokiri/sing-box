package route

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"
	"github.com/stretchr/testify/require"
)

type switchFlowManager struct {
	adapter.OutboundManager
	outbounds map[string]adapter.Outbound
}

func (m *switchFlowManager) Default() adapter.Outbound { return m.outbounds["choice"] }
func (m *switchFlowManager) Outbound(tag string) (adapter.Outbound, bool) {
	outbound, ok := m.outbounds[tag]
	return outbound, ok
}

type pausedFlowHandler struct {
	routeFlowHandler
	once           sync.Once
	judged, resume chan struct{}
}

func (h *pausedFlowHandler) JudgeFlowContext(ctx context.Context, network uint8, source, destination netip.AddrPort, first []byte) tun.FlowVerdict {
	verdict := h.routeFlowHandler.JudgeFlowContext(ctx, network, source, destination, first)
	h.once.Do(func() { close(h.judged); <-h.resume })
	return verdict
}

func TestFlowSelectorSwitch(t *testing.T) {
	for _, tc := range []struct {
		name                       string
		interrupt, nested, pending bool
	}{
		{"interrupt", true, false, false},
		{"preserve", false, false, false},
		{"nested", true, true, false},
		{"pending", true, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				a := &routeFlowPort{tag: "a", address: netip.MustParseAddr("127.0.0.1"), sent: make(chan []byte, 8)}
				b := &routeFlowPort{tag: "b", address: netip.MustParseAddr("127.0.0.2"), sent: make(chan []byte, 8)}
				manager := &switchFlowManager{outbounds: map[string]adapter.Outbound{"a": a, "b": b}}
				ctx := service.ContextWith[adapter.OutboundManager](context.Background(), manager)
				makeSelector := func(tag string, tags []string, interrupt bool) *group.Selector {
					outbound, err := group.NewSelector(ctx, nil, logger.NOP(), tag, option.SelectorOutboundOptions{Outbounds: tags, Default: tags[0], InterruptExistConnections: interrupt})
					require.NoError(t, err)
					s := outbound.(*group.Selector)
					manager.outbounds[tag] = s
					require.NoError(t, s.Start())
					return s
				}
				selectedTag := "choice"
				if tc.nested {
					selectedTag = "inner"
				}
				selector := makeSelector(selectedTag, []string{"a", "b"}, tc.interrupt)
				if tc.nested {
					makeSelector("choice", []string{"inner"}, false)
				}
				router := &Router{ctx: ctx, logger: logger.NOP(), outbound: manager, dns: &retryFlowDNS{}, dnsTransport: flowDNSManager{}}
				addFlowRules(t, router, `{"action":"route-options","udp_timeout":"5m"}`, `{"action":"route","outbound":"choice"}`)
				base := routeFlowHandler{router: router}
				var handler tun.Handler = base
				paused := &pausedFlowHandler{routeFlowHandler: base, judged: make(chan struct{}), resume: make(chan struct{})}
				if tc.pending {
					handler = paused
				}
				d := tun.NewForwardDispatcher(handler, flowWriteback{}, logger.NOP(), 5*time.Minute, time.Minute)
				d.EnableAsyncFlow(ctx, func([]byte) { t.Error("unexpected stack fallback") })
				defer d.Close()
				send := func(port uint16) {
					packet := dnsTestPacket(netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("203.0.113.1"), "data")
					header.UDP(header.IPv4(packet).Payload()).SetSourcePort(port)
					require.True(t, d.Dispatch(packet))
					d.Flush()
				}
				send(50000)
				if tc.pending {
					flowReceive(t, paused.judged)
				} else {
					flowReceive(t, a.sent)
				}
				synctest.Wait()
				require.True(t, selector.SelectOutbound("b"))
				if tc.pending {
					close(paused.resume)
					flowReceive(t, b.sent)
					require.Empty(t, a.sent, "a canceled pending verdict must not forward its first packet")
				}
				target, other := b, a
				if !tc.interrupt {
					target, other = a, b
				}
				for i := range 7 {
					if i > 0 {
						time.Sleep(4 * time.Minute)
					}
					send(50000)
					flowReceive(t, target.sent)
					synctest.Wait()
					require.Empty(t, other.sent)
				}
				send(50001)
				flowReceive(t, b.sent)
			})
		})
	}
}
