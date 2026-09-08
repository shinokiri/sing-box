package tun

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/logger"
	"github.com/stretchr/testify/require"
)

type inlinePendingHandler struct{ *pendingHandler }

func (h inlinePendingHandler) JudgeFlow(_ uint8, source, _ netip.AddrPort, first []byte) FlowVerdict {
	return h.judge(context.Background(), source, first)
}

type gatedWriteback struct {
	pendingWriteback
	entered, resume chan struct{}
	once            sync.Once
}

func (w *gatedWriteback) WriteReturnPackets(packets [][]byte) error {
	w.once.Do(func() { close(w.entered) })
	<-w.resume
	return w.pendingWriteback.WriteReturnPackets(packets)
}

func TestRejectWritebackDoesNotLockDispatcher(t *testing.T) {
	for _, async := range []bool{false, true} {
		name := "inline"
		if async {
			name = "async"
		}
		t.Run(name, func(t *testing.T) {
			port := &pendingPort{sent: make(chan []byte, 4)}
			h := inlinePendingHandler{&pendingHandler{judge: func(_ context.Context, source netip.AddrPort, _ []byte) FlowVerdict {
				if source.Port() == 50000 {
					return FlowVerdict{Action: ActionFlow, Port: port}
				}
				return FlowVerdict{Action: ActionReject}
			}}}
			w := &gatedWriteback{pendingWriteback: pendingWriteback{packets: make(chan []byte, 4)}, entered: make(chan struct{}), resume: make(chan struct{})}
			release := sync.OnceFunc(func() { close(w.resume) })
			d := NewForwardDispatcher(h, w, logger.NOP(), time.Minute, time.Minute)
			if async {
				d.EnableAsyncFlow(context.Background(), func([]byte) { t.Error("unexpected fallback") })
			}
			defer func() { release(); d.Close() }()
			d.Dispatch(pendingPacket(50000, []byte("establish")))
			d.Flush()
			pendingReceive(t, port.sent)
			if async {
				waitPendingIdle(t, d)
			}
			rejectDone := make(chan struct{})
			go func() {
				d.Dispatch(pendingPacket(50001, []byte("reject")))
				d.Flush()
				close(rejectDone)
			}()
			pendingReceive(t, w.entered)
			done := make(chan struct{})
			go func() {
				d.Dispatch(pendingPacket(50000, []byte("fast")))
				d.Flush()
				d.ResetNetwork()
				d.Close()
				close(done)
			}()
			pendingReceive(t, done) // Forwarding, reset and close all finish before I/O resumes.
			raw := pendingReceive(t, port.sent)
			require.Equal(t, "fast", string(header.UDP(header.IPv4(raw).Payload()).Payload()))
			release()
			pendingReceive(t, rejectDone)
			if async {
				waitPendingIdle(t, d)
			}
		})
	}
}

func TestPendingTransientRejectExpiresDuringWriteback(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		port := &pendingPort{sent: make(chan []byte, 4)}
		var calls atomic.Int32
		h := &pendingHandler{judge: func(context.Context, netip.AddrPort, []byte) FlowVerdict {
			if calls.Add(1) == 1 {
				return FlowVerdict{Action: ActionReject, RejectTimeout: time.Second}
			}
			return FlowVerdict{Action: ActionFlow, Port: port}
		}}
		w := &gatedWriteback{pendingWriteback: pendingWriteback{packets: make(chan []byte, 4)}, entered: make(chan struct{}), resume: make(chan struct{})}
		release := sync.OnceFunc(func() { close(w.resume) })
		d := NewForwardDispatcher(h, w, logger.NOP(), time.Minute, time.Minute)
		d.EnableAsyncFlow(context.Background(), func([]byte) { t.Error("unexpected fallback") })
		defer func() { release(); d.Close() }()
		d.Dispatch(pendingPacket(50000, []byte("first")))
		pendingReceive(t, w.entered)
		d.Dispatch(pendingPacket(50000, []byte("queued")))
		time.Sleep(2 * time.Second)
		release()
		raw := pendingReceive(t, port.sent)
		require.Equal(t, "queued", string(header.UDP(header.IPv4(raw).Payload()).Payload()))
		synctest.Wait()
		require.Equal(t, int32(2), calls.Load(), "queued traffic must obtain a fresh verdict after the failure expires")
		require.Zero(t, d.async.workers)
		require.Zero(t, d.async.bytes)
	})
}

func TestPolicyRejectKeepsIdleTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		h := &pendingHandler{judge: func(context.Context, netip.AddrPort, []byte) FlowVerdict {
			calls.Add(1)
			return FlowVerdict{Action: ActionReject}
		}}
		w := &pendingWriteback{packets: make(chan []byte, 4)}
		d := NewForwardDispatcher(h, w, logger.NOP(), 5*time.Minute, time.Minute)
		d.EnableAsyncFlow(context.Background(), func([]byte) { t.Error("unexpected fallback") })
		defer d.Close()
		send := func() {
			d.Dispatch(pendingPacket(50000, []byte("policy reject")))
			d.Flush()
			pendingReceive(t, w.packets)
			synctest.Wait()
		}
		send()
		for range 3 {
			time.Sleep(4 * time.Minute)
			send()
		}
		require.Equal(t, int32(1), calls.Load())
		time.Sleep(5*time.Minute + time.Nanosecond)
		send()
		require.Equal(t, int32(2), calls.Load())
	})
}
