//go:build linux

package snellv6

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/sagernet/sing-snell/internal/reuse"
	N "github.com/sagernet/sing/common/network"
)

func BenchmarkReadyPoolCheckout(b *testing.B) {
	for _, size := range []int{1, 10} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				b.Fatal(err)
			}
			defer listener.Close()
			client, err := NewClient(ClientOptions{PSK: []byte("public pool benchmark"), Reuse: true})
			if err != nil {
				b.Fatal(err)
			}
			defer client.Close()
			for i := 0; i < size; i++ {
				conn, err := net.Dial("tcp", listener.Addr().String())
				if err != nil {
					b.Fatal(err)
				}
				peer, err := listener.Accept()
				if err != nil {
					b.Fatal(err)
				}
				defer peer.Close()
				session := client.newReuseSession(conn)
				session.state.Store(uint32(reuse.StateActive))
				session.Release(true)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				session, found, closed := client.pool.Take()
				if !found || closed {
					b.Fatal("healthy session unavailable")
				}
				session.Release(true)
			}
			b.StopTimer()
		})
	}
}

func BenchmarkResponseTransportRead(b *testing.B) {
	psk := []byte("public response throughput fixture")
	payload := bytes.Repeat([]byte{42}, 16384)
	var payloads [][]byte
	for i := 0; i < 64; i++ {
		payloads = append(payloads, payload)
	}
	payloads = append(payloads, nil)
	wire, profile := receiveWire(b, psk, payloads)
	b.ReportAllocs()
	b.SetBytes(64 * 16384)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader, first, err := readFirstResponse(bytes.NewReader(wire), ModeDefault, psk, profile, N.ReadWaitOptions{})
		if err != nil {
			b.Fatal(err)
		}
		first.Release()
		for {
			body, err := reader.ReadRecord()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				b.Fatal(err)
			}
			body.Release()
		}
		releaseResponseReader(reader)
	}
}
