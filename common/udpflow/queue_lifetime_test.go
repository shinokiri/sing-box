package udpflow

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

type pausedQueuePacketConn struct {
	*channelPacketConn
	started, resume chan struct{}
}

func (c *pausedQueuePacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	if string(buffer.Bytes()) == "in-flight" {
		close(c.started)
		select {
		case <-c.resume:
		case <-c.closed:
			buffer.Release()
			return net.ErrClosed
		}
	}
	return c.channelPacketConn.WritePacket(buffer, destination)
}

func TestDispatcherUDPQueueKeepsOriginalFlow(t *testing.T) {
	for _, family := range []struct{ name, client, fakeA, fakeB, realA, realB string }{
		{"IPv4", "192.0.2.1", "198.18.0.1", "198.18.0.2", "203.0.113.1", "203.0.113.2"},
		{"IPv6", "2001:db8::1", "fc00::1", "fc00::2", "2001:db8::10", "2001:db8::20"},
	} {
		for _, mode := range []string{"dial-queue", "write-queue", "tun-batch"} {
			t.Run(family.name+"/"+mode, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					conn := &pausedQueuePacketConn{channelPacketConn: newChannelPacketConn(), started: make(chan struct{}), resume: make(chan struct{})}
					dialStarted := make(chan struct{}, 4)
					port, err := New(Options{DialPacketConn: func(ctx context.Context, _ M.Socksaddr) (N.NetPacketConn, error) {
						dialStarted <- struct{}{}
						if mode == "dial-queue" {
							select {
							case <-conn.resume:
							case <-ctx.Done():
								return nil, ctx.Err()
							}
						}
						return conn, nil
					}})
					require.NoError(t, err)
					defer port.Close()
					lifetime, cancel := context.WithCancel(context.Background())
					defer cancel()
					h := &replyFlowHandler{port: port, real: netip.MustParseAddr(family.realB)}
					d := tun.NewForwardDispatcher(h, newTestWriteback(), logger.NOP(), 5*time.Minute, time.Minute)
					defer d.Close()
					send := func(fake, payload string) {
						require.True(t, d.Dispatch(buildTestUDPPacket(t, netip.MustParseAddr(family.client), 50000, netip.MustParseAddr(fake), 443, []byte(payload))))
						if mode != "tun-batch" {
							d.Flush()
						}
					}
					first := "healthy"
					if mode == "write-queue" {
						first = "in-flight"
					}
					send(family.fakeB, first)
					if mode != "tun-batch" {
						receiveTestValue(t, dialStarted)
					}
					if mode == "write-queue" {
						receiveTestValue(t, conn.started)
					}
					h.real, h.lifetime = netip.MustParseAddr(family.realA), lifetime
					send(family.fakeA, "canceled-first")
					send(family.fakeA, "canceled-second")
					cancel()
					// Replace exactly the same tuple on the surviving association.
					// Looking it up at dequeue would incorrectly revive both old packets.
					h.lifetime = nil
					send(family.fakeA, "replacement")
					d.Flush()
					if mode == "tun-batch" {
						receiveTestValue(t, dialStarted)
					}
					time.Sleep(5 * time.Second)
					close(conn.resume)
					synctest.Wait()
					var sent []string
					for len(conn.sent) != 0 {
						sent = append(sent, string((<-conn.sent).payload))
					}
					require.Equal(t, []string{first, "replacement"}, sent)
					require.Empty(t, dialStarted, "unaffected flows must keep their association")
					require.Zero(t, port.queuedBytes, "discarded packets must release their byte budget")
					require.Len(t, port.flows, 1)
				})
			})
		}
	}
}

func TestDispatcherProtocolDiscardsCanceledQueue(t *testing.T) {
	for _, protocol := range []string{"snell-v4", "snell-v4-http", "snell-v6", "snell-v6-unshaped", "snell-v6-unsafe-raw", "vless-xudp"} {
		t.Run(protocol, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				packets := make(chan associationPacket, 8)
				dial := newProtocolTestDialer(t, protocol, &associationPacketHandler{packets: packets})
				started, resume := make(chan struct{}), make(chan struct{})
				port, err := New(Options{DialPacketConn: func(ctx context.Context, dst M.Socksaddr) (N.NetPacketConn, error) {
					close(started)
					select {
					case <-resume:
						return dial(ctx, dst)
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				}})
				require.NoError(t, err)
				defer port.Close()
				lifetime, cancel := context.WithCancel(context.Background())
				defer cancel()
				h := &replyFlowHandler{port: port, real: netip.MustParseAddr("203.0.113.1"), lifetime: lifetime}
				d := tun.NewForwardDispatcher(h, newTestWriteback(), logger.NOP(), time.Minute, time.Minute)
				defer d.Close()
				send := func(fake, payload string) {
					require.True(t, d.Dispatch(buildTestUDPPacket(t, netip.MustParseAddr("192.0.2.1"), 50000, netip.MustParseAddr(fake), 443, []byte(payload))))
					d.Flush()
				}
				send("198.18.0.1", "canceled")
				receiveTestValue(t, started)
				h.real, h.lifetime = netip.MustParseAddr("203.0.113.2"), nil
				send("198.18.0.2", "healthy")
				cancel()
				close(resume)
				require.Equal(t, "healthy", receiveTestValue(t, packets).payload)
				synctest.Wait()
				require.Empty(t, packets)
				require.Zero(t, port.queuedBytes)
			})
		})
	}
}
