//go:build linux && !android

package tun

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestGoKernelWindowLimitedRecovery(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		t.Run(fmt.Sprintf("ipv6=%v", ipv6), func(test *testing.T) {
			test.Parallel()
			fixture := newKernelStackFixture(test, kernelStackConfig{mtu: 9000})
			client, server := fixture.pair(test, ipv6)
			err := client.SetReadBuffer(4096)
			if err != nil {
				test.Fatal(err)
			}
			output, err := exec.Command("tc", "qdisc", "add", "dev", fixture.options.Name, "root", "netem", "delay", "50ms").CombinedOutput()
			if err != nil {
				test.Fatalf("delay ACKs: %s: %v", output, err)
			}
			payload := kernelPayload(8<<20, 223)
			initial := 4 * int(server.effectiveMSS)
			_, err = server.Write(payload[:initial])
			if err != nil {
				test.Fatal(err)
			}
			deadline := time.Now().Add(time.Second)
			for time.Now().Before(deadline) {
				if server.sendPermit.Load() == server.sendUnacked.Load() && server.sentTail.Load() > server.sendUnacked.Load()+2*uint64(server.effectiveMSS) {
					break
				}
				time.Sleep(time.Millisecond)
			}
			if server.sendPermit.Load() != server.sendUnacked.Load() || server.sentTail.Load() <= server.sendUnacked.Load()+2*uint64(server.effectiveMSS) {
				test.Fatal("window did not shrink below outstanding data")
			}
			completed := make(chan kernelIOResult, 1)
			server.SetWriteDeadline(time.Now().Add(2 * time.Second))
			go func() {
				n, writeErr := server.Write(payload[initial:])
				completed <- kernelIOResult{n: n + initial, err: writeErr}
			}()
			deadline = time.Now().Add(time.Second)
			for !server.writerParked.Load() && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if !server.writerParked.Load() {
				test.Fatal("write did not block at the closed window")
			}
			server.SetWriteDeadline(time.Now())
			var accepted int
			select {
			case result := <-completed:
				if !errors.Is(result.err, os.ErrDeadlineExceeded) || result.n <= 0 || result.n >= len(payload) {
					test.Fatalf("interrupt blocked write: %+v", result)
				}
				accepted = result.n
			case <-time.After(time.Second):
				test.Fatal("write did not react to deadline")
			}
			output, err = exec.Command("tc", "qdisc", "del", "dev", fixture.options.Name, "root").CombinedOutput()
			if err != nil {
				test.Fatalf("restore ACKs: %s: %v", output, err)
			}
			err = client.SetReadBuffer(4 << 20)
			if err != nil {
				test.Fatal(err)
			}
			rawConn, err := client.SyscallConn()
			if err != nil {
				test.Fatal(err)
			}
			var optionErr error
			err = rawConn.Control(func(descriptor uintptr) {
				optionErr = unix.SetsockoptInt(int(descriptor), unix.IPPROTO_TCP, unix.TCP_WINDOW_CLAMP, 6144)
			})
			if err != nil || optionErr != nil {
				test.Fatalf("limit receive window: %v %v", err, optionErr)
			}
			server.SetWriteDeadline(time.Now().Add(4 * time.Second))
			client.SetReadDeadline(time.Now().Add(4 * time.Second))
			go func() {
				n, writeErr := server.Write(payload[accepted:])
				if writeErr == nil {
					writeErr = server.CloseWrite()
				}
				completed <- kernelIOResult{n: n + accepted, err: writeErr}
			}()
			data, err := io.ReadAll(client)
			if err != nil || !bytes.Equal(data, payload) {
				test.Fatalf("window-limited recovery: received=%d/%d accepted=%d: %v", len(data), len(payload), accepted, err)
			}
			select {
			case result := <-completed:
				if result.err != nil || result.n != len(payload) {
					test.Fatalf("resume blocked write: %+v", result)
				}
			case <-time.After(time.Second):
				test.Fatal("write remained blocked after recovery")
			}
		})
	}
}

func TestGoKernelZeroWindow(t *testing.T) {
	fixture := newKernelStackFixture(t, kernelStackConfig{mtu: 9000})
	for _, ipv6 := range []bool{false, true} {
		t.Run(fmt.Sprintf("ipv6=%v", ipv6), func(test *testing.T) {
			client, server := fixture.pair(test, ipv6)
			err := client.SetReadBuffer(4096)
			if err != nil {
				test.Fatal(err)
			}
			runTC := func(args ...string) {
				test.Helper()
				output, commandErr := exec.Command("tc", args...).CombinedOutput()
				if commandErr != nil {
					test.Fatalf("tc %v: %s: %v", args, output, commandErr)
				}
			}
			runTC("qdisc", "replace", "dev", fixture.options.Name, "root", "netem", "delay", "50ms")
			payload := kernelPayload(32768, 107)
			_, err = server.Write(payload)
			if err != nil {
				test.Fatal(err)
			}
			deadline := time.Now().Add(time.Second)
			for time.Now().Before(deadline) {
				if server.sendPermit.Load() == server.sendUnacked.Load() && server.sentTail.Load() == server.bufferedTail.Load() {
					break
				}
				time.Sleep(time.Millisecond)
			}
			unacked := server.sendUnacked.Load()
			if server.sendPermit.Load() != unacked || server.sentTail.Load() != uint64(len(payload)+1) || unacked <= 1 || unacked >= server.sentTail.Load() {
				test.Fatalf("window did not close with only outstanding data: unacked=%d sent=%d buffered=%d permit=%d", unacked, server.sentTail.Load(), server.bufferedTail.Load(), server.sendPermit.Load())
			}
			runTC("qdisc", "replace", "dev", fixture.options.Name, "root", "netem", "loss", "100%")
			err = client.SetReadBuffer(4 << 20)
			if err != nil {
				test.Fatal(err)
			}
			data := make([]byte, len(payload))
			_, err = io.ReadFull(client, data[:unacked-1])
			if err != nil {
				test.Fatal(err)
			}
			time.Sleep(100 * time.Millisecond)
			runTC("qdisc", "del", "dev", fixture.options.Name, "root")
			client.SetReadDeadline(time.Now().Add(4 * time.Second))
			_, err = io.ReadFull(client, data[unacked-1:])
			if err != nil {
				test.Fatal("recover lost window update:", err)
			}
			if !bytes.Equal(data, payload) {
				test.Fatal("zero-window recovery corrupted the stream")
			}
		})
	}
}
