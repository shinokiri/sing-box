//go:build (linux && !android) || (darwin && !ios) || windows

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

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

func TestGoKernelFlowControl(t *testing.T) {
	previous := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(previous)
	configs := []kernelStackConfig{{mtu: 1500}, {mtu: 9000}, {mtu: 65535}}
	if runtime.GOOS == "linux" {
		configs = append(configs, kernelStackConfig{mtu: 1500, gso: true, multiQueue: true}, kernelStackConfig{mtu: 9000, gso: true, multiQueue: true})
	}
	for _, config := range configs {
		t.Run(fmt.Sprintf("mtu=%d/gso=%v/mq=%v", config.mtu, config.gso, config.multiQueue), func(configTest *testing.T) {
			config.socketBuffer = 128 << 10
			config.upstreamSocketBuffer = 128 << 10
			fixture := newKernelStackFixture(configTest, config)
			for _, ipv6 := range []bool{false, true} {
				for _, mode := range []string{"write", "buffer", "splice"} {
					configTest.Run(fmt.Sprintf("ipv6=%v/mode=%s", ipv6, mode), func(test *testing.T) {
						test.Parallel()
						size := 4 << 20
						if runtime.GOOS == "windows" && mode == "splice" {
							size = 16 << 20
						}
						kernelBackpressure(test, fixture, ipv6, mode, size)
					})
				}
			}
		})
	}
}

func kernelBackpressure(t *testing.T, fixture *kernelStackFixture, ipv6 bool, mode string, size int) {
	t.Helper()
	var client, server net.Conn
	if mode == "splice" {
		client, server, _, _ = fixture.splicePair(t, ipv6)
	} else {
		client, server = fixture.pair(t, ipv6)
	}
	err := client.(*net.TCPConn).SetReadBuffer(4096)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("flow %s -> %s", client.LocalAddr(), client.RemoteAddr())
	deadline := time.Now().Add(10 * time.Second)
	client.SetDeadline(deadline)
	server.SetDeadline(deadline)
	upload := kernelPayload(size, 113)
	download := kernelPayload(size, 127)
	var uploadAccepted, downloadAccepted atomic.Int64
	written := make(chan error, 2)
	go func() { written <- kernelFlowWrite(client, upload, false, &uploadAccepted) }()
	go func() { written <- kernelFlowWrite(server, download, mode == "buffer", &downloadAccepted) }()
	time.Sleep(100 * time.Millisecond)
	if uploadAccepted.Load() == int64(len(upload)) || downloadAccepted.Load() == int64(len(download)) {
		t.Fatalf("stalled readers did not backpressure both writers: upload=%d download=%d", uploadAccepted.Load(), downloadAccepted.Load())
	}
	read := make(chan error, 2)
	go func() { read <- kernelFlowRead(server, upload, mode == "buffer") }()
	go func() { read <- kernelFlowRead(client, download, false) }()
	for range 2 {
		err = <-read
		if err != nil {
			t.Error(err)
		}
	}
	for range 2 {
		err = <-written
		if err != nil {
			t.Error(err)
		}
	}
}

func kernelFlowWrite(conn net.Conn, payload []byte, buffered bool, accepted *atomic.Int64) error {
	for offset := 0; offset < len(payload); {
		length := min(32749, len(payload)-offset)
		var n int
		var err error
		if buffered {
			buffer := buf.NewSize(length + 128)
			buffer.Resize(128, 0)
			common.Must1(buffer.Write(payload[offset : offset+length]))
			err = conn.(N.ExtendedWriter).WriteBuffer(buffer)
			if err == nil {
				n = length
			}
		} else {
			n, err = conn.Write(payload[offset : offset+length])
		}
		offset += n
		accepted.Add(int64(n))
		if err != nil {
			return E.Cause(err, "write flow after ", offset, " bytes")
		}
	}
	return N.CloseWrite(conn)
}

func kernelFlowRead(conn net.Conn, payload []byte, buffered bool) error {
	var waiter N.ReadWaiter
	if buffered {
		var created bool
		waiter, created = bufio.CreateReadWaiter(conn)
		if !created {
			return E.New("flow connection has no read waiter")
		}
		waiter.InitializeReadWaiter(N.ReadWaitOptions{MTU: 4093, FrontHeadroom: 91, RearHeadroom: 73})
	}
	storage := make([]byte, 16381)
	sizes := [...]int{1, 127, 4093, len(storage)}
	paused := 0
	for offset, index := 0, 0; ; index++ {
		if offset/65536 > paused && paused < 4 && offset < len(payload) {
			paused = offset / 65536
			time.Sleep(25 * time.Millisecond)
		}
		var data []byte
		var buffer *buf.Buffer
		var err error
		if buffered {
			buffer, err = waiter.WaitReadBuffer()
			if buffer != nil {
				data = buffer.Bytes()
			}
		} else {
			var n int
			n, err = conn.Read(storage[:sizes[index%len(sizes)]])
			data = storage[:n]
		}
		end := offset + len(data)
		matches := end <= len(payload) && bytes.Equal(data, payload[offset:min(end, len(payload))])
		if buffer != nil {
			buffer.ExtendHeader(91)
			buffer.Extend(73)
			buffer.Release()
		}
		if !matches {
			return E.New("flow mismatch at byte ", offset)
		}
		offset = end
		if err == io.EOF && offset == len(payload) {
			return nil
		}
		if err != nil {
			return E.Cause(err, "read flow after ", offset, "/", len(payload), " bytes")
		}
	}
}
