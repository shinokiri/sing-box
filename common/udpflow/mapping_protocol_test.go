package udpflow

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

type associationPacket struct {
	association int
	payload     string
}
type associationPacketHandler struct {
	N.TCPConnectionHandlerEx
	id      int
	packets chan associationPacket
}

func (h *associationPacketHandler) NewPacketConnectionEx(_ context.Context, conn N.PacketConn, _, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	go func() {
		defer conn.Close()
		for {
			buffer := buf.NewSize(65535)
			target, err := conn.ReadPacket(buffer)
			if err != nil {
				buffer.Release()
				return
			}
			h.packets <- associationPacket{h.id, string(buffer.Bytes())}
			target.Port = 40000
			if _, err = bufio.WritePacketBuffer(conn, buffer, target); err != nil {
				return
			}
		}
	}()
}

func TestDispatcherProtocolCollisionFollowup(t *testing.T) {
	for _, protocol := range []string{"snell-v4", "snell-v4-http", "snell-v6", "snell-v6-unshaped", "snell-v6-unsafe-raw", "vless-xudp"} {
		t.Run(protocol, func(t *testing.T) {
			packets := make(chan associationPacket, 8)
			// The third connection makes an accidental redial observable at the
			// real protocol server, instead of failing with a mock dial error.
			dials := make([]PacketConnFactory, 3)
			for i := range dials {
				dials[i] = newProtocolTestDialer(t, protocol, &associationPacketHandler{id: i, packets: packets})
			}
			var count atomic.Int32
			port, err := New(Options{DialPacketConn: func(ctx context.Context, dst M.Socksaddr) (N.NetPacketConn, error) {
				return dials[count.Add(1)-1](ctx, dst)
			}})
			require.NoError(t, err)
			defer port.Close()
			fake, real := netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr("203.0.113.1")
			w := newTestWriteback()
			d := tun.NewForwardDispatcher(&replyFlowHandler{port: port, real: real}, w, logger.NOP(), time.Minute, time.Minute)
			defer d.Close()
			for i, packet := range []struct {
				client  string
				target  uint16
				payload string
			}{
				{"192.0.2.1", 69, "client A"},
				{"192.0.2.2", 69, "client B initial"},
				{"192.0.2.2", 40000, "client B follow-up"},
			} {
				require.True(t, d.Dispatch(buildTestUDPPacket(t, netip.MustParseAddr(packet.client), 50000, fake, packet.target, []byte(packet.payload))))
				d.Flush()
				received := receiveTestValue(t, packets)
				require.Equal(t, packet.payload, received.payload)
				require.Equal(t, min(i, 1), received.association, "follow-up must retain the server-side association")
				_, dest, payload, ok := parseUDPPacket(receiveTestValue(t, w.packets))
				require.True(t, ok)
				require.Equal(t, netip.AddrPortFrom(netip.MustParseAddr(packet.client), 50000), dest)
				require.Equal(t, packet.payload, string(payload))
			}
			require.Equal(t, int32(2), count.Load())
		})
	}
}
