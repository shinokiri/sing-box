package udpflow

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

func TestPortFailureBackoffAndRecovery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		var recovered atomic.Bool
		conn := newChannelPacketConn()
		port, err := New(Options{DialPacketConn: func(context.Context, M.Socksaddr) (N.NetPacketConn, error) {
			calls.Add(1)
			if recovered.Load() {
				return conn, nil
			}
			return nil, errors.New("connection refused")
		}})
		require.NoError(t, err)
		defer port.Close()
		for range 100 {
			require.NoError(t, port.WritePackets([][]byte{testPortPacket(t, 50000, "failed")}))
			synctest.Wait()
			time.Sleep(10 * time.Millisecond)
		}
		require.Equal(t, int32(4), calls.Load(), "fast failures must not retry at packet rate")
		recovered.Store(true)
		require.NoError(t, port.WritePackets([][]byte{testPortPacket(t, 50000, "recovered")}))
		require.Equal(t, "recovered", string(receiveTestValue(t, conn.sent).payload))
		for range 10 {
			require.NoError(t, port.WritePackets([][]byte{testPortPacket(t, 50000, "healthy")}))
			require.Equal(t, "healthy", string(receiveTestValue(t, conn.sent).payload))
		}
		synctest.Wait()
		require.Equal(t, int32(5), calls.Load())
		require.Empty(t, port.failures)
		require.Zero(t, port.queuedBytes)
	})
}

func TestPortBackoffIsolationAndReset(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		port, err := New(Options{MaxFlows: 4, DialPacketConn: func(context.Context, M.Socksaddr) (N.NetPacketConn, error) {
			calls.Add(1)
			return nil, errors.New("connection refused")
		}})
		require.NoError(t, err)
		defer port.Close()
		a, err := port.ForInbound("a")
		require.NoError(t, err)
		b, err := port.ForInbound("b")
		require.NoError(t, err)
		packet := testPortPacket(t, 50000, "failed")
		require.NoError(t, a.WritePackets([][]byte{packet}))
		synctest.Wait()
		require.NoError(t, b.WritePackets([][]byte{packet}))
		synctest.Wait()
		require.Equal(t, int32(2), calls.Load(), "one inbound's cooldown must not affect another")
		port.Reset()
		require.NoError(t, a.WritePackets([][]byte{packet}))
		synctest.Wait()
		require.Equal(t, int32(3), calls.Load(), "network reset must allow immediate recovery")
		for selector := uint16(50001); selector < 50020; selector++ {
			require.NoError(t, a.WritePackets([][]byte{testPortPacket(t, selector, "new source")}))
			synctest.Wait()
		}
		require.LessOrEqual(t, len(port.failures), port.maxFlows)
		require.Empty(t, port.flows)
		require.Zero(t, port.queuedBytes)
		time.Sleep(failedAssociationBackoff)
		port.sweep()
		require.Empty(t, port.failures)
	})
}
