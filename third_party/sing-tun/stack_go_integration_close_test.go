//go:build (linux && !android) || (darwin && !ios) || windows

package tun

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"syscall"
	"testing"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

func TestGoKernelClose(t *testing.T) {
	previous := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(previous)
	t.Run("reset", func(scenarioTest *testing.T) {
		fixture := newKernelStackFixture(scenarioTest, kernelStackConfig{mtu: 1500})
		for _, ipv6 := range []bool{false, true} {
			client, conn := fixture.pair(scenarioTest, ipv6)
			client.SetLinger(0)
			client.Close()
			_, err := conn.Read(make([]byte, 1))
			if !errors.Is(err, syscall.ECONNRESET) {
				scenarioTest.Errorf("reset ipv6=%v: %v", ipv6, err)
			}
		}
	})
	t.Run("drain_after_fin", func(scenarioTest *testing.T) {
		fixture := newKernelStackFixture(scenarioTest, kernelStackConfig{mtu: 1500})
		for _, ipv6 := range []bool{false, true} {
			client, conn := fixture.pair(scenarioTest, ipv6)
			payload := kernelPayload(32769, 41)
			_, err := client.Write(payload)
			if err != nil {
				scenarioTest.Fatal(err)
			}
			client.CloseWrite()
			conn.CloseWrite()
			_, err = io.ReadAll(client)
			if err != nil {
				scenarioTest.Fatal(err)
			}
			data, err := io.ReadAll(conn)
			if err != nil || !bytes.Equal(data, payload) {
				scenarioTest.Fatalf("drain ipv6=%v bytes=%d: %v", ipv6, len(data), err)
			}
		}
	})
	for _, splice := range []bool{false, true} {
		t.Run(fmt.Sprintf("busy_shutdown/splice=%v", splice), func(scenarioTest *testing.T) {
			fixture := newKernelStackFixture(scenarioTest, kernelStackConfig{mtu: 1500, multiQueue: runtime.GOOS == "linux"})
			payload := kernelPayload(8<<20, 33)
			completed := make(chan error, 32)
			for index := range 16 {
				var client, conn net.Conn
				if splice {
					client, conn, _, _ = fixture.splicePair(scenarioTest, index%2 != 0)
				} else {
					client, conn = fixture.pair(scenarioTest, index%2 != 0)
				}
				client.SetDeadline(time.Time{})
				client.(*net.TCPConn).SetReadBuffer(4096)
				conn.SetDeadline(time.Time{})
				go func() { conn.Write(payload); completed <- nil }()
				go func() {
					_, err := conn.Read(make([]byte, 1))
					if err == nil {
						completed <- E.New("pending read completed without close error")
						return
					}
					completed <- nil
				}()
			}
			time.Sleep(30 * time.Millisecond)
			started := time.Now()
			err := fixture.stack.Close()
			if err != nil {
				scenarioTest.Fatal(err)
			}
			if time.Since(started) > time.Second {
				scenarioTest.Error("stack close exceeded 1 second")
			}
			deadline := time.NewTimer(2 * time.Second)
			defer deadline.Stop()
			for range 32 {
				select {
				case operationErr := <-completed:
					if operationErr != nil {
						scenarioTest.Error(operationErr)
					}
				case <-deadline.C:
					scenarioTest.Fatal("pending I/O did not unblock after stack shutdown")
				}
			}
			for _, engine := range fixture.stack.engines {
				inUse := engine.slabPool.inUse.Load()
				if inUse != 0 {
					scenarioTest.Errorf("shutdown retained %d allocated slabs", inUse)
				}
			}
		})
	}
}
