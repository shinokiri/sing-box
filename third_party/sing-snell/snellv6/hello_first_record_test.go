package snellv6

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Decode the SYN-sized envelope without making the remaining TCP bytes
// available. A one-byte growth past the boundary must not make previously
// deliverable application data depend on a later segment's authentication tag.
func TestHelloFirstRecordHasNoPayloadCliff(t *testing.T) {
	for keyID := 0; keyID < 3; keyID++ {
		key := []byte(fmt.Sprintf("public first record fixture %d", keyID))
		for _, budget := range []int{496, 1180, 1292, 1392, 4181} {
			// IPv4 destination and no user key: 18 request bytes, plus 141
			// carrier/salt/authentication bytes for one complete record.
			limit := budget - 159
			for _, size := range []int{1, 278, 381, 512, limit - 1, limit, limit + 1, 1506, 1793, 8192} {
				for _, path := range []string{"write", "buffer", "vector-split", "vector-large-first"} {
					for _, reuse := range []bool{false, true} {
						t.Run(fmt.Sprintf("key%d/budget%d/size%d/%s/reuse%v", keyID, budget, size, path, reuse), func(t *testing.T) {
							transport, err := NewHelloTransportWithOptions(key, HelloTransportOptions{InitialSYNDataLimit: budget})
							if err != nil {
								t.Fatal(err)
							}
							var info HelloFrameInfo
							frames := 0
							transport.OnFirstFrame = func(row HelloFrameInfo) { info = row; frames++ }
							raw := new(helloMemoryConn)
							physical := transport.Wrap(helloVectorMemoryConn{raw}, "test")
							client, err := NewClient(ClientOptions{PSK: key, Reuse: reuse, Dialer: helloMemoryDialer{conn: physical}, Server: M.ParseSocksaddr("192.0.2.1:443")})
							if err != nil {
								t.Fatal(err)
							}
							defer client.Close()
							target := M.ParseSocksaddr("203.0.113.17:443")
							conn, err := client.DialContext(context.Background(), target)
							if err != nil {
								t.Fatal(err)
							}
							want := make([]byte, size)
							for i := range want {
								want[i] = byte(i * 37)
							}
							if path == "write" {
								_, err = conn.Write(want)
							} else {
								parts := [][]byte{want}
								if path == "vector-split" {
									cut := min(97, len(want))
									parts = [][]byte{nil, want[:cut], nil, want[cut:], nil}
								} else if path == "vector-large-first" {
									cut := min(limit+1, len(want))
									parts = [][]byte{want[:cut], want[cut:]}
								}
								front, rear := N.CalculateFrontHeadroom(conn), N.CalculateRearHeadroom(conn)
								var buffers []*buf.Buffer
								for _, part := range parts {
									b := buf.NewSize(front + len(part) + rear)
									b.Resize(front, 0)
									_, _ = b.Write(part)
									buffers = append(buffers, b)
								}
								if path == "buffer" {
									err = bufio.NewExtendedWriter(conn).WriteBuffer(buffers[0])
								} else {
									err = bufio.NewVectorisedWriter(conn).WriteVectorised(buffers)
								}
							}
							if err != nil {
								t.Fatal(err)
							}
							if info.Budget != budget || info.WireBytes > budget || (info.Mode != 0 && info.Mode != 1) {
								t.Fatal(info)
							}
							if info.Mode == 1 && info.WireBytes != min(size, limit)+159 {
								t.Fatal("compact first record size changed", info)
							}
							if info.Mode == 0 && info.OriginalBytes != info.InitialWriteBytes {
								t.Fatal("prefix optimization lost early original bytes", info)
							}
							request := snell.Request{Command: snell.CommandConnectV2, Destination: target}
							requestBuffer := buf.NewSize(request.Len())
							defer requestBuffer.Release()
							if err = request.Write(requestBuffer); err != nil {
								t.Fatal(err)
							}
							wire := bytes.NewReader(raw.Bytes())
							prefix, err := transport.DecodeHello(wire)
							if err != nil {
								t.Fatal(err)
							}
							earlyReader := newShapedReader(bytes.NewReader(prefix), key, NewProfile(key))
							early, err := earlyReader.ReadRecord()
							if err != nil {
								t.Fatal("first record still needs a later packet", err)
							}
							wantEarly := append(append([]byte(nil), requestBuffer.Bytes()...), want[:min(size, limit)]...)
							if !bytes.Equal(early.Bytes(), wantEarly) {
								t.Fatal("early authenticated payload differs", early.Len(), len(wantEarly))
							}
							early.Release()
							if extra, e := earlyReader.ReadRecord(); e != io.EOF {
								if extra != nil {
									extra.Release()
								}
								t.Fatal("unexpected extra early record", e)
							}
							later := []byte("later write stays on the ordinary record path")
							if _, err = conn.Write(later); err != nil {
								t.Fatal(err)
							}
							fullWire := bytes.NewReader(raw.Bytes())
							prefix, err = transport.DecodeHello(fullWire)
							if err != nil {
								t.Fatal(err)
							}
							reader := newShapedReader(io.MultiReader(bytes.NewReader(prefix), fullWire), key, NewProfile(key))
							var full []byte
							for {
								b, e := reader.ReadRecord()
								if e == io.EOF {
									break
								}
								if e != nil {
									t.Fatal(e)
								}
								full = append(full, b.Bytes()...)
								b.Release()
							}
							wantFull := append(append(append([]byte(nil), requestBuffer.Bytes()...), want...), later...)
							if !bytes.Equal(full, wantFull) || frames != 1 {
								t.Fatal("remaining stream changed or reframed", len(full), frames)
							}
						})
					}
				}
			}
		}
	}
}

func TestHelloFirstRecordOverrideIsPhysicalAndOneTime(t *testing.T) {
	profile := NewProfile(helloTestPSK)
	transport, _ := NewHelloTransportWithOptions(helloTestPSK, HelloTransportOptions{InitialSYNDataLimit: 1392})
	physical := transport.Wrap(new(helloMemoryConn), "test").(*helloConn)
	ordinary := newShapedWriter(io.Discard, profile, nil, nil, nil)
	framed := newShapedWriter(physical, profile, nil, nil, nil)
	request := buf.NewSize(64)
	defer request.Release()
	if err := (snell.Request{Command: snell.CommandConnectV2, Destination: M.ParseSocksaddr("192.0.2.2:443")}).Write(request); err != nil {
		t.Fatal(err)
	}
	framed.firstPayloadLimit = helloFirstRecordLimit(physical, request.Bytes())
	now := time.Unix(100, 0)
	if ordinary.payloadLimitFor(now) > profile.firstRecordCap {
		t.Fatal("ordinary first record changed")
	}
	if got := framed.payloadLimitFor(now); got != 1251 {
		t.Fatal(got)
	}
	// Both writers advance the same normal dynamic state after their first record.
	for seq := uint32(1); seq < 40; seq++ {
		ordinary.seq, framed.seq = seq, seq
		if ordinary.payloadLimitFor(now) != framed.payloadLimitFor(now) {
			t.Fatal("later shaping changed", seq)
		}
	}
	physical.sent.Store(true)
	if _, active := helloFirstPayloadLimit(physical); active {
		t.Fatal("reused physical connection got a new first record budget")
	}
	if _, active := helloFirstPayloadLimit(net.Conn(new(helloMemoryConn))); active {
		t.Fatal("ordinary connection got a carrier budget")
	}
}

func TestHelloSmallCapacityKeepsRequestHeaderWhole(t *testing.T) {
	for _, budget := range []int{helloMinBudget, 143, 159, 496} {
		for _, long := range []bool{false, true} {
			transport, _ := NewHelloTransportWithOptions(helloTestPSK, HelloTransportOptions{InitialSYNDataLimit: budget})
			raw := new(helloMemoryConn)
			physical := transport.Wrap(raw, "test")
			var userKey []byte
			target := M.ParseSocksaddr("example.test:443")
			if long {
				userKey = bytes.Repeat([]byte{1}, 255)
				target = M.Socksaddr{Fqdn: strings.Repeat("a", 200) + ".test", Port: 443}
			}
			client, err := NewClient(ClientOptions{PSK: helloTestPSK, UserKey: userKey})
			if err != nil {
				t.Fatal(err)
			}
			conn := client.DialEarlyConn(physical, target)
			if _, err = conn.Write([]byte("application bytes")); err != nil {
				t.Fatal(budget, long, err)
			}
			wire := bytes.NewReader(raw.Bytes())
			prefix, err := transport.DecodeHello(wire)
			if err != nil {
				t.Fatal(err)
			}
			reader := newShapedReader(io.MultiReader(bytes.NewReader(prefix), wire), helloTestPSK, NewProfile(helloTestPSK))
			record, err := reader.ReadRecord()
			if err != nil {
				t.Fatal(err)
			}
			request, err := snell.ReadRequest(record)
			record.Release()
			if err != nil || request.Destination != target || !bytes.Equal(request.ClientID, userKey) {
				t.Fatal("request header split", budget, long, err)
			}
			client.Close()
		}
	}
}
