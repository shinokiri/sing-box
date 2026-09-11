//go:build darwin && !ios

package tun

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

func TestGoKernelDeviceBackpressure(t *testing.T) {
	previous := runtime.GOMAXPROCS(4)
	t.Cleanup(func() { runtime.GOMAXPROCS(previous) })
	for _, mtu := range []uint32{1500, 9000} {
		for _, shutdown := range []bool{false, true} {
			t.Run(fmt.Sprintf("mtu=%d/shutdown=%v", mtu, shutdown), func(test *testing.T) {
				fixture := newKernelStackFixture(test, kernelStackConfig{mtu: mtu, prepare: prepareKernelNetif})
				platform := fixture.stack.engines[0].platformIO.(*goDarwinIO)
				if !platform.netif {
					test.Fatal("utun netif was not enabled")
				}
				observed := make(chan struct{}, 1)
				stop := make(chan struct{})
				defer close(stop)
				go func() {
					ticker := time.NewTicker(50 * time.Microsecond)
					defer ticker.Stop()
					for {
						select {
						case <-ticker.C:
							if platform.gateBlocked.Load() {
								observed <- struct{}{}
								return
							}
						case <-stop:
							return
						}
					}
				}()
				payload := kernelPayload(32<<20, 223)
				written := make(chan error, 8)
				read := make(chan error, 8)
				start := make(chan struct{})
				var clients []net.Conn
				for index := range 8 {
					var client, server net.Conn
					splice := index%2 != 0
					if splice {
						client, server, _, _ = fixture.splicePair(test, index%4 >= 2)
					} else {
						client, server = fixture.pair(test, index%4 >= 2)
					}
					clients = append(clients, client)
					go func() {
						<-start
						var accepted atomic.Int64
						written <- kernelFlowWrite(server, payload, !splice, &accepted)
					}()
					go func() {
						<-start
						data, err := io.ReadAll(io.LimitReader(client, int64(len(payload)+1)))
						if err == nil && !bytes.Equal(data, payload) {
							err = E.New("device backpressure payload mismatch")
						}
						read <- err
					}()
				}
				close(start)
				select {
				case <-observed:
				case <-time.After(3 * time.Second):
					test.Fatal("real netif transmit gate never became blocked")
				}
				if shutdown {
					started := time.Now()
					err := fixture.stack.Close()
					if err != nil || time.Since(started) > time.Second {
						test.Fatalf("close during device backpressure: %v", err)
					}
				}
				interrupted := 0
				limit := time.After(12 * time.Second)
				if shutdown {
					limit = time.After(time.Second)
				}
				for range 8 {
					select {
					case err := <-written:
						if shutdown {
							if E.IsTimeout(err) {
								test.Error("device-blocked I/O timed out after close:", err)
							}
							if err != nil {
								interrupted++
							}
						} else if err != nil {
							test.Error("transfer after device backpressure:", err)
						}
					case <-limit:
						test.Fatal("device-blocked I/O did not complete")
					}
				}
				if shutdown && interrupted == 0 {
					test.Error("all writers finished before shutdown")
				}
				if shutdown {
					for _, client := range clients {
						client.Close()
					}
				}
				for range 8 {
					select {
					case err := <-read:
						if !shutdown && err != nil {
							test.Error("read after device backpressure:", err)
						}
					case <-limit:
						test.Fatal("device backpressure reader did not complete")
					}
				}
				if platform.leakedClusters.total.Load() != 0 {
					test.Fatal("utun reported ENOSPC while applying device backpressure")
				}
			})
		}
	}
}

func TestGoKernelMemoryPressureTransition(t *testing.T) {
	previous := runtime.GOMAXPROCS(4)
	t.Cleanup(func() { runtime.GOMAXPROCS(previous) })
	for _, netif := range []bool{false, true} {
		for _, ipv6 := range []bool{false, true} {
			for _, splice := range []bool{false, true} {
				t.Run(fmt.Sprintf("netif=%v/ipv6=%v/splice=%v", netif, ipv6, splice), func(test *testing.T) {
					test.Parallel()
					var pressure, observed atomic.Uint32
					config := kernelStackConfig{mtu: 1500, socketBuffer: 128 << 10, upstreamSocketBuffer: 128 << 10}
					config.pressure = func() MemoryPressure {
						level := pressure.Load()
						observed.Or(1 << level)
						return MemoryPressure(level)
					}
					if netif {
						config.prepare = prepareKernelNetif
					}
					fixture := newKernelStackFixture(test, config)
					var client, server net.Conn
					if splice {
						client, server, _, _ = fixture.splicePair(test, ipv6)
					} else {
						client, server = fixture.pair(test, ipv6)
					}
					const phaseSize = 4 << 20
					upload := kernelPayload(3*phaseSize, 227)
					download := kernelPayload(3*phaseSize, 229)
					var uploadAccepted, downloadAccepted atomic.Int64
					written := make(chan error, 2)
					go func() { written <- kernelFlowWrite(client, upload, false, &uploadAccepted) }()
					go func() { written <- kernelFlowWrite(server, download, !splice, &downloadAccepted) }()
					time.Sleep(100 * time.Millisecond)
					if uploadAccepted.Load() == int64(len(upload)) || downloadAccepted.Load() == int64(len(download)) {
						test.Fatal("pressure transition requires both writers to be active")
					}
					for phase, level := range []MemoryPressure{MemoryPressureWarning, MemoryPressureCritical, MemoryPressureNone} {
						observed.And(^(1 << uint32(level)))
						pressure.Store(uint32(level))
						read := make(chan error, 2)
						for direction, conn := range []net.Conn{server, client} {
							expected := upload
							if direction == 1 {
								expected = download
							}
							go func() {
								data := make([]byte, phaseSize)
								_, err := io.ReadFull(conn, data)
								if err == nil && !bytes.Equal(data, expected[phase*phaseSize:(phase+1)*phaseSize]) {
									err = E.New("pressure transition payload mismatch")
								}
								read <- err
							}()
						}
						for range 2 {
							err := <-read
							if err != nil {
								test.Fatal("active stream pressure transition:", err)
							}
						}
						if observed.Load()&(1<<uint32(level)) == 0 {
							test.Fatalf("pressure level %d was not observed during transfer", level)
						}
					}
					for range 2 {
						err := <-written
						if err != nil {
							test.Fatal(err)
						}
					}
					for _, conn := range []net.Conn{server, client} {
						_, err := conn.Read(make([]byte, 1))
						if err != io.EOF {
							test.Fatalf("EOF after pressure transitions: %v", err)
						}
					}
				})
			}
		}
	}
}
