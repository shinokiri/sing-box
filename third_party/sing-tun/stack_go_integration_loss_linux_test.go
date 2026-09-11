//go:build linux && !android

package tun

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"testing"
)

func configureKernelLoss(t *testing.T, options Options) {
	t.Helper()
	ifbName := "ifb-" + options.Name
	commands := [][]string{
		{"ip", "link", "add", ifbName, "type", "ifb"},
		{"ip", "link", "set", ifbName, "up"},
		{"tc", "qdisc", "add", "dev", options.Name, "root", "netem", "delay", "2ms", "1ms", "loss", "1%", "reorder", "10%", "50%", "limit", "4096"},
		{"tc", "qdisc", "add", "dev", options.Name, "ingress"},
		{"tc", "filter", "add", "dev", options.Name, "parent", "ffff:", "protocol", "all", "u32", "match", "u32", "0", "0", "action", "mirred", "egress", "redirect", "dev", ifbName},
		{"tc", "qdisc", "add", "dev", ifbName, "root", "netem", "delay", "2ms", "1ms", "loss", "1%", "reorder", "10%", "50%", "limit", "4096"},
	}
	for index, command := range commands {
		output, err := exec.Command(command[0], command[1:]...).CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %s: %v", command, output, err)
		}
		if index == 0 {
			t.Cleanup(func() { exec.Command("ip", "link", "delete", ifbName).Run() })
		}
	}
}

func TestGoKernelBidirectionalLoss(t *testing.T) {
	previous := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(previous)
	for _, gso := range []bool{false, true} {
		for _, multiQueue := range []bool{false, true} {
			t.Run(fmt.Sprintf("gso=%v/mq=%v", gso, multiQueue), func(offloadTest *testing.T) {
				fixture := newKernelStackFixture(offloadTest, kernelStackConfig{mtu: 1500, gso: gso, multiQueue: multiQueue, configure: configureKernelLoss})
				for _, ipv6 := range []bool{false, true} {
					for _, splice := range []bool{false, true} {
						offloadTest.Run(fmt.Sprintf("ipv6=%v/splice=%v", ipv6, splice), func(flowTest *testing.T) {
							flowTest.Parallel()
							var client, server net.Conn
							if splice {
								client, server, _, _ = fixture.splicePair(flowTest, ipv6)
							} else {
								client, server = fixture.pair(flowTest, ipv6)
							}
							payload := kernelPayload(1<<20, 43)
							response := kernelPayload(1<<20, 47)
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
				}
			})
		}
	}
}
