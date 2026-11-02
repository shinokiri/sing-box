//go:build linux

package dialer

import (
	"fmt"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
)

func TestPlatformTFOCellularPreparedBinding(t *testing.T) {
	for _, family := range []string{"tcp4", "tcp6"} {
		for _, cellular := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/cellular=%v", family, cellular), func(t *testing.T) {
				ctx := tfoContext(t, adapter.NetworkOptions{}, nil)
				manager := service.FromContext[adapter.NetworkManager](ctx).(*tfoNetworkManager)
				publish := func(cell bool, handle uint64) {
					manager.interfaces[0].Type = C.InterfaceTypeWIFI
					if cell {
						manager.interfaces[0].Type = C.InterfaceTypeCellular
					}
					manager.interfaces[0].NetworkHandle = handle
					manager.tfoState.Store(adapter.NewNetworkTFOState(manager.loopback.Index, manager.interfaces))
				}
				publish(cellular, 101)
				options := tfoOptions(t, `{"tcp_fast_open":true}`)
				d, err := newNetworkTFODialer(ctx, options)
				if err != nil {
					t.Fatal(err)
				}
				d.selectTFO4 = newNetworkTFOSelector(&d.dialer4, manager, options, testMarkNetwork, true)
				d.selectTFO6 = newNetworkTFOSelector(&d.dialer6, manager, options, testMarkNetwork, true)
				destination := networkTFOListener(t, family)
				conn, err := d.DialContext(ctx, family, destination)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				preparer := conn.(interface{ PrepareTFO() (bool, uint64) })
				if compat, handle := preparer.PrepareTFO(); compat != cellular || handle != 101 {
					t.Fatalf("prepared compat=%v handle=%d", compat, handle)
				}
				// The Hello is now being encoded. A network event must not change
				// its marker's meaning or the socket selected by the first Write.
				publish(!cellular, 102)
				if compat, handle := preparer.PrepareTFO(); compat != cellular || handle != 101 {
					t.Fatal("prepared policy changed during framing")
				}
				if err := networkTFOExchange(conn, true); err != nil {
					t.Fatal(err)
				}
				if socketMark(t, conn) != 101 {
					t.Fatal("socket used a different network than its Hello")
				}
				next, err := d.DialContext(ctx, family, destination)
				if err != nil {
					t.Fatal(err)
				}
				defer next.Close()
				if compat, handle := next.(interface{ PrepareTFO() (bool, uint64) }).PrepareTFO(); compat != !cellular || handle != 102 {
					t.Fatal("new connection did not adopt the new network")
				}
				if err := networkTFOExchange(next, true); err != nil {
					t.Fatal(err)
				}
				if socketMark(t, next) != 102 {
					t.Fatal("new socket retained old binding")
				}
			})
		}
	}
}

func TestPlatformTFOCellularRequiresOptInAndIdentity(t *testing.T) {
	for _, optIn := range []bool{false, true} {
		for _, known := range []bool{false, true} {
			ctx := tfoContext(t, adapter.NetworkOptions{}, nil)
			manager := service.FromContext[adapter.NetworkManager](ctx).(*tfoNetworkManager)
			manager.interfaces[0].Type = C.InterfaceTypeCellular
			if known {
				manager.interfaces[0].NetworkHandle = 101
			}
			manager.tfoState.Store(adapter.NewNetworkTFOState(manager.loopback.Index, manager.interfaces))
			d, err := newNetworkTFODialer(ctx, tfoOptions(t, `{"tcp_fast_open":true}`))
			if err != nil {
				t.Fatal(err)
			}
			selectChoice := newNetworkTFOSelector(&d.dialer4, manager, option.DialerOptions{}, testNetworkBind, optIn)
			choice := selectChoice()
			want := optIn && known
			if choice.cellularCompat != want || choice.DisableTFO == want {
				t.Fatalf("opt-in=%v known=%v choice=%+v", optIn, known, choice)
			}
			if n := testing.AllocsPerRun(1000, func() { _ = selectChoice() }); n != 0 {
				t.Fatalf("cached cellular selection allocates: %v", n)
			}
		}
	}
}
