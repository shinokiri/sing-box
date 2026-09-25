package adapter

import (
	"net/netip"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/control"
)

func TestNetworkTFOExplicitSource(t *testing.T) {
	wifiIP := netip.MustParseAddr("192.0.2.1")
	cellIP := netip.MustParseAddr("2001:db8::1")
	interfaces := []NetworkInterface{
		{Interface: control.Interface{Name: "wifi", Index: 1, Addresses: []netip.Prefix{netip.PrefixFrom(wifiIP, 24)}}, Type: C.InterfaceTypeWIFI},
		{Interface: control.Interface{Name: "cell", Index: 2, Addresses: []netip.Prefix{netip.PrefixFrom(cellIP, 64)}}, Type: C.InterfaceTypeCellular},
	}
	state := NewNetworkTFOState(2, interfaces)
	for _, tc := range []struct {
		name string
		address netip.Addr
		want bool
	}{
		{"", netip.Addr{}, false},
		{"wifi", netip.Addr{}, true},
		{"cell", netip.Addr{}, false},
		{"", wifiIP, true},
		{"wifi", wifiIP, true},
		{"cell", wifiIP, false},
		{"", cellIP, false},
		{"wifi", cellIP, false},
		{"missing", netip.Addr{}, false},
		{"", netip.MustParseAddr("192.0.2.9"), false},
	} {
		if got := state.Allowed(tc.name, tc.address); got != tc.want {
			t.Fatalf("interface=%s address=%v allowed=%v want=%v", tc.name, tc.address, got, tc.want)
		}
	}
	interfaces[1].Addresses = append(interfaces[1].Addresses, netip.PrefixFrom(wifiIP, 24))
	if NewNetworkTFOState(1, interfaces).Allowed("", wifiIP) {
		t.Fatal("ambiguous source address was classified as non-cellular")
	}
	if !state.Allowed("", wifiIP) {
		t.Fatal("published state retained mutable interface slices")
	}
}
