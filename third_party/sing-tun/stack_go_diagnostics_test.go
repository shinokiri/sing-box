//go:build linux && !android

package tun

import (
	"net"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func kernelDiagnoseFlow(t *testing.T, client, server net.Conn) func() {
	c, ok := server.(*GoConn)
	if !ok {
		return func() {}
	}
	done, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for tick := 1; ; tick++ {
			select {
			case <-done:
				return
			case <-ticker.C:
				t.Logf("diagnostic tick=%d mss=%d state=%d send: unacked=%d released=%d sent=%d transmitted=%d buffered=%d permit=%d packets=%d/%d active=%d parked=%v needs=%d owner=%d transmitter=%d signals=%d/%d pacing=%d/%d read: consumed=%d available=%d ack=%d edge=%d sentEdge=%d capacity=%d threshold=%d active=%d parked=%v target=%v done=%v signal=%d", tick, c.effectiveMSS, c.connState.Load(), c.sendUnacked.Load(), c.sendReleased.Load(), c.sentTail.Load(), c.transmittedTail.Load(), c.bufferedTail.Load(), c.sendPermit.Load(), c.dataSegmentsOut.Load(), c.sendPacketPermit.Load(), c.writerActive.Load(), c.writerParked.Load(), c.writerNeeds.Load(), c.transmitOwner.Load(), c.transmitterActive.Load(), len(c.writeSignal), len(c.transmitSignal), c.pacingRate.Load(), c.pacingStamp.Load(), c.consumedTail.Load(), c.receiveAvailable.Load(), c.receiveNextAck.Load(), c.receiveEdge.Load(), c.sentEdge.Load(), c.receiveCapacityPublished.Load(), c.windowUpdateThreshold.Load(), c.readerActive.Load(), c.readerParked.Load(), c.postedTarget.Load() != nil, c.targetDone.Load(), len(c.readSignal))
				raw, err := client.(*net.TCPConn).SyscallConn()
				if err == nil {
					raw.Control(func(fd uintptr) {
						info, infoErr := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
						t.Logf("diagnostic TCP_INFO=%+v error=%v", info, infoErr)
					})
				}
				if tick == 3 {
					stacks := make([]byte, 1<<20)
					n := runtime.Stack(stacks, true)
					t.Logf("diagnostic goroutines:\n%s", stacks[:n])
				}
			}
		}
	}()
	return func() { close(done); <-stopped }
}
