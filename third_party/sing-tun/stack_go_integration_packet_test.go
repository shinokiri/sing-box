//go:build (linux && !android) || (darwin && !ios) || windows

package tun

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestGoKernelPacketTimeout(t *testing.T) {
	fixture := newKernelStackFixture(t, kernelStackConfig{mtu: 1500})
	for _, ipv6 := range []bool{false, true} {
		t.Run(fmt.Sprintf("ipv6=%v", ipv6), func(test *testing.T) {
			client, conn, destination := fixture.packetPair(test, ipv6)
			if !conn.SetTimeout(100 * time.Millisecond) {
				test.Fatal("cannot set live UDP session timeout")
			}
			buffer, _, err := conn.WaitReadPacket()
			if buffer != nil {
				buffer.Release()
			}
			if !errors.Is(err, io.ErrClosedPipe) {
				test.Fatalf("idle UDP session did not close: %v", err)
			}
			payload := kernelPayload(1200, 103)
			_, err = client.Write(payload)
			if err != nil {
				test.Fatal(err)
			}
			fixture.access.Lock()
			accepted := fixture.udp[destination.Port]
			fixture.access.Unlock()
			select {
			case replacement := <-accepted:
				defer replacement.Close()
				replacement.SetReadDeadline(time.Now().Add(time.Second))
				packet := buf.NewPacket()
				defer packet.Release()
				_, err = replacement.ReadPacket(packet)
				if err != nil || !bytes.Equal(packet.Bytes(), payload) {
					test.Fatalf("UDP session renewal lost its first packet: %v", err)
				}
				err = replacement.WritePacket(buf.As(payload), destination)
				if err != nil {
					test.Fatal(err)
				}
				response := make([]byte, 1500)
				n, readErr := client.Read(response)
				if readErr != nil || !bytes.Equal(response[:n], payload) {
					test.Fatalf("renewed UDP session response: %v", readErr)
				}
			case <-time.After(time.Second):
				test.Fatal("next UDP packet did not create a new session")
			}
		})
	}
}

func TestGoKernelPacketBuffer(t *testing.T) {
	fixture := newKernelStackFixture(t, kernelStackConfig{mtu: 1500})
	for _, ipv6 := range []bool{false, true} {
		t.Run(fmt.Sprintf("ipv6=%v", ipv6), func(addressTest *testing.T) {
			client, conn, destination := fixture.packetPair(addressTest, ipv6)
			for _, size := range []int{0, 1, 1473} {
				for _, capacity := range []int{0, 1, 1024, 2048} {
					addressTest.Run(fmt.Sprintf("size=%d/capacity=%d", size, capacity), func(packetTest *testing.T) {
						payload := kernelPayload(size, uint32(size+71))
						_, err := client.Write(payload)
						if err != nil {
							packetTest.Fatal(err)
						}
						prefix := []byte("prefix")
						buffer := buf.With(make([]byte, 16+len(prefix)+capacity+32))
						buffer.Resize(16, len(prefix))
						buffer.Reserve(32)
						copy(buffer.Bytes(), prefix)
						actualDestination, readErr := conn.ReadPacket(buffer)
						if capacity == 0 {
							if !errors.Is(readErr, io.ErrShortBuffer) {
								packetTest.Fatalf("full buffer: %v", readErr)
							}
						} else if readErr != nil {
							packetTest.Fatal(readErr)
						}
						if actualDestination != destination {
							packetTest.Fatalf("destination: %v, want %v", actualDestination, destination)
						}
						if buffer.Start() != 16 || !bytes.Equal(buffer.Bytes(), append(prefix, payload[:min(size, capacity)]...)) {
							packetTest.Fatalf("packet buffer: %x", buffer.Bytes())
						}
						marker := kernelPayload(7, 83)
						_, err = client.Write(marker)
						if err != nil {
							packetTest.Fatal(err)
						}
						buffer.Reset()
						_, err = conn.ReadPacket(buffer)
						if err != nil || !bytes.Equal(buffer.Bytes(), marker) {
							packetTest.Fatalf("next datagram: %x: %v", buffer.Bytes(), err)
						}
					})
				}
			}
		})
	}
}

func (f *kernelStackFixture) packetPair(t *testing.T, ipv6 bool) (*net.UDPConn, *UDPNatConn, M.Socksaddr) {
	t.Helper()
	port := uint16(20000 + f.port.Add(1))
	accepted := make(chan N.PacketConn, 1)
	f.access.Lock()
	f.udp[port] = accepted
	f.access.Unlock()
	destination := M.ParseSocksaddr(f.address(ipv6, port))
	client, err := net.DialUDP("udp", nil, destination.UDPAddr())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	err = client.SetWriteBuffer(1 << 20)
	if err != nil {
		t.Fatal(err)
	}
	client.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = client.Write([]byte("ready"))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case conn := <-accepted:
		t.Cleanup(func() { conn.Close() })
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		buffer := buf.NewPacket()
		_, err = conn.ReadPacket(buffer)
		buffer.Release()
		if err != nil {
			t.Fatal(err)
		}
		return client, conn.(*UDPNatConn), destination
	case <-time.After(3 * time.Second):
		t.Fatal("UDP flow not accepted")
		return nil, nil, M.Socksaddr{}
	}
}

type kernelPacketSocket struct {
	*net.UDPConn
	access sync.Mutex
	owner  io.Closer
}

func (s *kernelPacketSocket) Attach(owner io.Closer) bool {
	s.access.Lock()
	s.owner = owner
	s.access.Unlock()
	return true
}

func (s *kernelPacketSocket) Detach() {
	s.access.Lock()
	s.owner = nil
	s.access.Unlock()
}

func TestGoKernelPacket(t *testing.T) {
	previous := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(previous)
	configs := []kernelStackConfig{{mtu: 1500}, {mtu: 65535}}
	if runtime.GOOS == "linux" {
		configs = append(configs, kernelStackConfig{mtu: 1500, gso: true, multiQueue: true})
	}
	for _, config := range configs {
		t.Run(fmt.Sprintf("mtu=%d/gso=%v/mq=%v", config.mtu, config.gso, config.multiQueue), func(configurationTest *testing.T) {
			fixture := newKernelStackFixture(configurationTest, config)
			for _, ipv6 := range []bool{false, true} {
				configurationTest.Run(fmt.Sprintf("ipv6=%v", ipv6), func(addressTest *testing.T) {
					for _, splice := range []bool{false, true} {
						addressTest.Run(fmt.Sprintf("splice=%v", splice), func(scenarioTest *testing.T) {
							client, conn, destination := fixture.packetPair(scenarioTest, ipv6)
							var peer *net.UDPConn
							var upstream *net.UDPConn
							if splice {
								var err error
								network := "udp4"
								address := net.IPv4(127, 0, 0, 1)
								if ipv6 {
									network = "udp6"
									address = net.IPv6loopback
								}
								peer, err = net.ListenUDP(network, &net.UDPAddr{IP: address})
								if err != nil {
									scenarioTest.Fatal(err)
								}
								scenarioTest.Cleanup(func() { peer.Close() })
								upstream, err = net.DialUDP(network, nil, peer.LocalAddr().(*net.UDPAddr))
								if err != nil {
									scenarioTest.Fatal(err)
								}
								scenarioTest.Cleanup(func() { upstream.Close() })
								peer.SetWriteBuffer(1 << 20)
								upstream.SetWriteBuffer(1 << 20)
								peer.SetDeadline(time.Now().Add(3 * time.Second))
								accepted := conn.Splice(&kernelPacketSocket{UDPConn: upstream}, SplicePacketOptions{
									NAT:           PacketNAT{Origin: destination, Destination: M.SocksaddrFromNet(peer.LocalAddr())},
									SpliceOptions: SpliceOptions{OnClose: func(error) { upstream.Close() }},
								})
								if !accepted {
									scenarioTest.Fatal("UDP splice refused")
								}
							}
							sizes := []int{0, 1, 1472, 1473, 8193, 65507}
							if ipv6 {
								sizes = append(sizes, 1452, 1453, 65527)
							}
							for _, size := range sizes {
								scenarioTest.Run(fmt.Sprintf("size=%d", size), func(packetTest *testing.T) {
									payload := kernelPayload(size, uint32(size+37))
									_, err := client.Write(payload)
									if err != nil {
										packetTest.Fatal("kernel upload:", err)
									}
									var received []byte
									if splice {
										data := make([]byte, 65535)
										n, source, readErr := peer.ReadFromUDP(data)
										if readErr != nil {
											packetTest.Fatal("spliced upload:", readErr)
										}
										received = data[:n]
										_, err = peer.WriteToUDP(payload, source)
									} else {
										buffer := buf.NewSize(65535)
										_, err = conn.ReadPacket(buffer)
										received = bytes.Clone(buffer.Bytes())
										buffer.Release()
										if err != nil {
											packetTest.Fatal("Go upload:", err)
										}
										err = conn.WritePacket(buf.As(payload), destination)
									}
									if !bytes.Equal(received, payload) {
										packetTest.Fatalf("upload bytes=%d want=%d", len(received), size)
									}
									if err != nil {
										packetTest.Fatal("download write:", err)
									}
									response := make([]byte, 65535)
									n, readErr := client.Read(response)
									if readErr != nil {
										packetTest.Fatal("kernel download:", readErr)
									}
									if !bytes.Equal(response[:n], payload) {
										packetTest.Fatalf("download bytes=%d want=%d", n, size)
									}
								})
							}
						})
					}
				})
			}
		})
	}
}

var _ SpliceSocket = (*kernelPacketSocket)(nil)
