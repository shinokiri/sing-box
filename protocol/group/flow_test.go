package group

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/interrupt"
	"github.com/sagernet/sing-box/common/urltest"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

type flowTestOutbound struct {
	adapter.Outbound
	tag     string
	network []string
}

func (o *flowTestOutbound) Tag() string       { return o.tag }
func (o *flowTestOutbound) Network() []string { return o.network }

func TestURLTestFlowSelectionAndInterruption(t *testing.T) {
	for _, interruptExisting := range []bool{false, true} {
		tcp := &flowTestOutbound{tag: "tcp", network: []string{N.NetworkTCP}}
		udpA := &flowTestOutbound{tag: "udp-a", network: []string{N.NetworkUDP}}
		udpB := &flowTestOutbound{tag: "udp-b", network: []string{N.NetworkUDP}}
		history := urltest.NewHistoryStorage()
		history.StoreURLTestHistory("tcp", &adapter.URLTestHistory{Delay: 1})
		history.StoreURLTestHistory("udp-a", &adapter.URLTestHistory{Delay: 10})
		history.StoreURLTestHistory("udp-b", &adapter.URLTestHistory{Delay: 100})
		g := &URLTestGroup{outbounds: []adapter.Outbound{tcp, udpA, udpB}, history: history, interruptGroup: interrupt.NewGroup(), interruptExternalConnections: interruptExisting}
		s := &URLTest{group: g, interruptExternalConnections: interruptExisting}
		g.performUpdateCheck()
		require.Same(t, tcp, s.Selected(N.NetworkTCP))
		require.Same(t, udpA, s.Selected(N.NetworkUDP))
		selected, lifetime := s.SelectedForFlow(N.NetworkUDP)
		require.Same(t, udpA, selected, "UDP must use its network-specific selection")
		history.StoreURLTestHistory("udp-b", &adapter.URLTestHistory{Delay: 1})
		g.performUpdateCheck()
		if interruptExisting {
			require.ErrorIs(t, lifetime.Err(), context.Canceled)
		} else {
			require.Nil(t, lifetime)
		}
		require.Same(t, udpB, s.Selected(N.NetworkUDP))
		selected, lifetime = s.SelectedForFlow(N.NetworkUDP)
		require.Same(t, udpB, selected)
		if lifetime != nil {
			require.NoError(t, lifetime.Err())
		}
	}
}
