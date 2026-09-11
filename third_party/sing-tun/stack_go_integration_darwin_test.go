//go:build darwin && !ios

package tun

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"sync/atomic"
	"testing"

	"golang.org/x/sys/unix"
)

const (
	kernelConnectionRefused = unix.ECONNREFUSED
	kernelConnectionReset   = unix.ECONNRESET
)

func TestGoKernelMemoryPressure(t *testing.T) {
	previous := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(previous)
	configs := []kernelStackConfig{{mtu: 1500}, {mtu: 1500, prepare: prepareKernelNetif}, {mtu: 9000, prepare: prepareKernelNetif}}
	for _, config := range configs {
		t.Run(fmt.Sprintf("mtu=%d/netif=%v", config.mtu, config.prepare != nil), func(configTest *testing.T) {
			var pressure atomic.Uint32
			config.pressure = func() MemoryPressure { return MemoryPressure(pressure.Load()) }
			fixture := newKernelStackFixture(configTest, config)
			configTest.Logf("utun netif mode: %v", fixture.stack.engines[0].platformIO.(*goDarwinIO).netif)
			for _, level := range []MemoryPressure{MemoryPressureWarning, MemoryPressureCritical, MemoryPressureNone} {
				configTest.Run(fmt.Sprintf("level=%d", level), func(test *testing.T) {
					pressure.Store(uint32(level))
					for _, splice := range []bool{false, true} {
						test.Run(fmt.Sprintf("splice=%v", splice), func(flowTest *testing.T) {
							var client, server net.Conn
							if splice {
								client, server, _, _ = fixture.splicePair(flowTest, true)
							} else {
								client, server = fixture.pair(flowTest, true)
							}
							payload := kernelPayload(8<<20, 79)
							response := kernelPayload(8<<20, 83)
							result := make(chan error, 1)
							go func() { result <- kernelTransfer(client, server, payload, false) }()
							err := kernelTransfer(server, client, response, !splice)
							if err != nil {
								flowTest.Error("download:", err)
							}
							err = <-result
							if err != nil {
								flowTest.Error("upload:", err)
							}
						})
					}
				})
			}
		})
	}
}

func prepareKernelNetif(t *testing.T, options *Options) {
	t.Helper()
	socketFD, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, sysprotoControl)
	if err != nil {
		t.Fatal(err)
	}
	transferred := false
	defer func() {
		if !transferred {
			unix.Close(socketFD)
		}
	}()
	var controlInfo unix.CtlInfo
	copy(controlInfo.Name[:], utunControlName)
	err = unix.IoctlCtlInfo(socketFD, &controlInfo)
	if err != nil {
		t.Fatal(err)
	}
	var index int
	_, err = fmt.Sscanf(options.Name, "utun%d", &index)
	if err != nil {
		t.Fatal(err)
	}
	address := &unix.SockaddrCtl{ID: controlInfo.Id, Unit: uint32(index + 1)}
	err = unix.Bind(socketFD, address)
	if err != nil {
		t.Fatal(err)
	}
	err = unix.SetsockoptInt(socketFD, sysprotoControl, utunOptionEnableNetif, 1)
	if err != nil {
		t.Fatal(err)
	}
	err = unix.Connect(socketFD, address)
	if err != nil {
		t.Fatal(err)
	}
	options.FileDescriptor = socketFD
	transferred = true
}

func configureKernelInterface(t *testing.T, device Tun, options Options) {
	t.Helper()
	ipv4 := options.Inet4Address[0]
	ipv6 := options.Inet6Address[0]
	commands := [][]string{
		{"/sbin/ifconfig", options.Name, "mtu", fmt.Sprint(options.MTU)},
		{"/sbin/ifconfig", options.Name, "inet", ipv4.Addr().String(), ipv4.Addr().String(), "netmask", "255.255.255.0", "up"},
		{"/sbin/ifconfig", options.Name, "inet6", ipv6.String(), "-dad"},
		{"/sbin/route", "-n", "add", "-net", ipv4.Masked().String(), "-interface", options.Name},
	}
	for _, command := range commands {
		output, err := exec.Command(command[0], command[1:]...).CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %s: %v", command, output, err)
		}
	}
}
