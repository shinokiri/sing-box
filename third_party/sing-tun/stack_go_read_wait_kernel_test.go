//go:build (linux && !android) || (darwin && !ios) || windows

package tun

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
)

func TestGoKernelReadWaitBatch(t *testing.T) {
	for _, memory := range []bool{false, true} {
		if memory && (testing.Short() || runtime.GOOS == "windows") {
			continue
		}
		t.Run(fmt.Sprintf("memory=%v", memory), func(t *testing.T) {
			fixture := newKernelStackFixture(t, kernelStackConfig{mtu: 1500, memoryLink: memory})
			for _, ipv6 := range []bool{false, true} {
				t.Run(fmt.Sprintf("ipv6=%v", ipv6), func(t *testing.T) {
					client, server := fixture.pair(t, ipv6)
					client.SetDeadline(time.Now().Add(15 * time.Second))
					server.SetDeadline(time.Now().Add(15 * time.Second))
					payload := kernelPayload(4<<20, 71)
					written := make(chan error, 1)
					go func() {
						_, err := client.Write(payload)
						if err == nil {
							err = client.CloseWrite()
						}
						written <- err
					}()
					writer := new(goReadWaitRecorder)
					n, err := bufio.Copy(writer, server)
					if err != nil || n != int64(len(payload)) || !bytes.Equal(writer.Bytes(), payload) {
						t.Fatalf("kernel copy n=%d err=%v", n, err)
					}
					if err := <-written; err != nil {
						t.Fatal(err)
					}
					if writer.batchCount == 0 || writer.largestBatch > goMaxReadBatch {
						t.Fatal("copy did not enter bounded vector path")
					}
					t.Logf("bulk transfer: %d vector calls, largest %d buffers", writer.batchCount, writer.largestBatch)
				})
			}
		})
	}
}

func TestGoKernelReadWaitBatchParked(t *testing.T) {
	fixture := newKernelStackFixture(t, kernelStackConfig{mtu: 1500})
	for _, action := range []string{"message", "deadline", "close"} {
		t.Run(action, func(t *testing.T) {
			client, server := fixture.pair(t, false)
			waiter, _ := server.CreateVectorisedReadWaiter()
			waiter.InitializeReadWaiter(N.ReadWaitOptions{BatchSize: 8})
			// Exercise a read parked before data, deadline, or local close arrives.
			result := make(chan error, 1)
			go func() {
				buffers, err := waiter.WaitReadBuffers()
				if action == "message" {
					if err == nil && (len(buffers) != 1 || string(buffers[0].Bytes()) != "one message") {
						err = fmt.Errorf("unexpected message batch: %d buffers", len(buffers))
					}
				}
				for _, buffer := range buffers {
					buffer.Release()
				}
				result <- err
			}()
			deadline := time.Now().Add(time.Second)
			for !server.readerParked.Load() && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if !server.readerParked.Load() {
				server.Close()
				<-result
				t.Fatal("reader did not park")
			}
			switch action {
			case "message":
				if _, err := io.WriteString(client, "one message"); err != nil {
					t.Fatal(err)
				}
			case "deadline":
				server.SetReadDeadline(time.Now())
			case "close":
				server.Close()
			}
			select {
			case err := <-result:
				if action == "message" && err != nil {
					t.Fatal(err)
				}
				if action == "deadline" && !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatalf("read deadline: %v", err)
				}
				if action == "close" && !errors.Is(err, net.ErrClosed) {
					t.Fatalf("read close: %v", err)
				}
			case <-time.After(time.Second):
				server.Close()
				<-result
				t.Fatal("parked reader did not resume")
			}
		})
	}
}
