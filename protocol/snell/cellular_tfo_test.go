package snell

import (
	"context"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestSnellCellularTFORejectsUnpairedConfiguration(t *testing.T) {
	for _, options := range []option.SnellOutboundOptions{
		{Version: 4, AbstractSnellOutboundOptions: option.AbstractSnellOutboundOptions{CellularTFOCompat: true}},
		{Version: 6, AbstractSnellOutboundOptions: option.AbstractSnellOutboundOptions{CellularTFOCompat: true}},
		{Version: 6, AbstractSnellOutboundOptions: option.AbstractSnellOutboundOptions{CellularTFOCompat: true, HelloFraming: true}},
		{Version: 6, AbstractSnellOutboundOptions: option.AbstractSnellOutboundOptions{CellularTFOCompat: true, HelloFraming: true, DialerOptions: option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{TCPFastOpen: true}, Detour: "another-outbound"}}},
	} {
		_, err := NewOutbound(context.Background(), nil, nil, "test", options)
		if err == nil || !strings.Contains(err.Error(), "cellular_tfo_compat") {
			t.Fatal("invalid opt-in was not rejected before dialing", err)
		}
	}
}
