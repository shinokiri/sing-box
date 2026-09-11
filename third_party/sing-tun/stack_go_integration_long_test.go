//go:build (linux && !android) || (darwin && !ios) || windows

package tun

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

func TestGoKernelSequenceWrap(t *testing.T) {
	previous := runtime.GOMAXPROCS(4)
	t.Cleanup(func() { runtime.GOMAXPROCS(previous) })
	fixture := newKernelStackFixture(t, kernelStackConfig{mtu: 1500, gso: runtime.GOOS == "linux"})
	for _, ipv6 := range []bool{false, true} {
		for _, mode := range []string{"write", "buffer", "splice"} {
			t.Run(fmt.Sprintf("ipv6=%v/mode=%s", ipv6, mode), func(test *testing.T) {
				test.Parallel()
				var client, server net.Conn
				if mode == "splice" {
					client, server, _, _ = fixture.splicePair(test, ipv6)
				} else {
					client, server = fixture.pair(test, ipv6)
				}
				deadline := time.Now().Add(60 * time.Second)
				client.SetDeadline(deadline)
				server.SetDeadline(deadline)
				completed := make(chan error, 1)
				go func() { completed <- kernelWrapTransfer(client, server, false) }()
				err := kernelWrapTransfer(server, client, mode == "buffer")
				if err != nil {
					test.Error("download:", err)
				}
				err = <-completed
				if err != nil {
					test.Error("upload:", err)
				}
			})
		}
	}
}

func kernelWrapTransfer(sender net.Conn, receiver net.Conn, buffered bool) error {
	const total = uint64(1)<<32 | 123
	const blockSize = 32768
	pattern := kernelPayload(blockSize, 53)
	completed := make(chan error, 1)
	go func() {
		block := bytes.Clone(pattern)
		for offset := uint64(0); offset < total; {
			length := min(uint64(blockSize), total-offset)
			binary.BigEndian.PutUint64(block, offset)
			var err error
			if buffered {
				buffer := buf.NewSize(int(length) + 128)
				buffer.Resize(128, 0)
				common.Must1(buffer.Write(block[:length]))
				err = sender.(N.ExtendedWriter).WriteBuffer(buffer)
			} else {
				_, err = sender.Write(block[:length])
			}
			if err != nil {
				completed <- err
				return
			}
			offset += length
		}
		completed <- N.CloseWrite(sender)
	}()
	block := make([]byte, blockSize)
	for offset := uint64(0); offset < total; {
		length := min(uint64(blockSize), total-offset)
		_, err := io.ReadFull(receiver, block[:length])
		if err != nil {
			return E.Cause(err, "read sequence offset ", offset)
		}
		if binary.BigEndian.Uint64(block) != offset || !bytes.Equal(block[8:length], pattern[8:length]) {
			return E.New("sequence data mismatch at ", offset)
		}
		offset += length
	}
	_, err := receiver.Read(block[:1])
	if err != io.EOF {
		return E.New("sequence stream end: ", err)
	}
	return <-completed
}
