package snellv6

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var helloTestPSK = []byte("public-hello-transport-test-key")

type helloMemoryConn struct {
	bytes.Buffer
	writes int
	short  bool
	closed bool
}

func (c *helloMemoryConn) Write(p []byte) (int, error) {
	c.writes++
	if c.short {
		return len(p) / 2, nil
	}
	return c.Buffer.Write(p)
}
func (c *helloMemoryConn) Close() error { c.closed = true; return nil }
func (*helloMemoryConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
}
func (*helloMemoryConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443}
}
func (*helloMemoryConn) SetDeadline(time.Time) error      { return nil }
func (*helloMemoryConn) SetReadDeadline(time.Time) error  { return nil }
func (*helloMemoryConn) SetWriteDeadline(time.Time) error { return nil }

func TestHelloTransportPreservesCiphertextAcrossWritePaths(t *testing.T) {
	for _, size := range []int{1, 128, 2048, 65535} {
		for _, path := range []string{"write", "buffer", "vector"} {
			plain := bytes.Repeat([]byte{0x71}, size)
			wire, _ := receiveWire(t, helloTestPSK, [][]byte{plain})
			transport, err := NewHelloTransport(helloTestPSK)
			if err != nil {
				t.Fatal(err)
			}
			var metadata HelloFrameInfo
			frames := 0
			transport.OnFirstFrame = func(info HelloFrameInfo) { metadata = info; frames++ }
			raw := new(helloMemoryConn)
			conn := transport.Wrap(raw, "ignored").(*helloConn)
			if conn.WriterReplaceable() {
				t.Fatal("first framing can be bypassed")
			}
			switch path {
			case "write":
				_, err = conn.Write(wire)
			case "buffer":
				b := buf.NewSize(len(wire))
				_, _ = b.Write(wire)
				err = conn.WriteBuffer(b)
			case "vector":
				// Separate salt/header/body fragments must form one first write.
				var buffers []*buf.Buffer
				for _, fragment := range [][]byte{wire[:3], wire[3:17], wire[17:]} {
					b := buf.NewSize(len(fragment))
					_, _ = b.Write(fragment)
					buffers = append(buffers, b)
				}
				err = conn.WriteVectorised(buffers)
			}
			if err != nil {
				t.Fatalf("size%d %s: %v", size, path, err)
			}
			if frames != 1 || metadata.WireBytes > helloColdBudget || metadata.BudgetSource != "cold_estimate" {
				t.Fatal(metadata, frames)
			}
			encoded := append([]byte(nil), raw.Bytes()...)
			reader := bytes.NewReader(encoded)
			prefix, err := transport.DecodeHello(reader)
			if err != nil {
				t.Fatal(err)
			}
			rest, _ := io.ReadAll(reader)
			if !bytes.Equal(append(prefix, rest...), wire) {
				t.Fatalf("ciphertext changed: size%d %s", size, path)
			}
			if !conn.WriterReplaceable() {
				t.Fatal("later writes cannot use existing fast path")
			}
			before := raw.Len()
			tail := []byte("already-encrypted-later-record")
			b := buf.NewSize(len(tail))
			_, _ = b.Write(tail)
			if err = conn.WriteVectorised([]*buf.Buffer{b}); err != nil {
				t.Fatal(err)
			}
			if frames != 1 || !bytes.Equal(raw.Bytes()[before:], tail) {
				t.Fatal("later record framed again")
			}
		}
	}
}

func TestHelloTransportClosesOnPartialFirstWrite(t *testing.T) {
	transport, _ := NewHelloTransport(helloTestPSK)
	raw := &helloMemoryConn{short: true}
	conn := transport.Wrap(raw, "target").(*helloConn)
	wire, _ := receiveWire(t, helloTestPSK, [][]byte{[]byte("test application bytes")})
	n, err := conn.Write(wire)
	if n != 0 || !errors.Is(err, io.ErrShortWrite) || !raw.closed || conn.WriterReplaceable() {
		t.Fatal(n, err, raw.closed)
	}
	_, err = conn.Write(wire)
	if !errors.Is(err, io.ErrShortWrite) || raw.writes != 1 {
		t.Fatal("failed frame was retried", err, raw.writes)
	}
}

func TestHelloCapacityGenerationExpiryAndPeerIsolation(t *testing.T) {
	transport, _ := NewHelloTransport(helloTestPSK)
	clock := time.Unix(1, 0)
	transport.now = func() time.Time { return clock }
	raw := new(helloMemoryConn)
	if size, source := transport.budget(raw, "v4-peer", 0); size != helloColdBudget || source != "cold_estimate" {
		t.Fatal(size, source)
	}
	if !transport.remember("v4-peer", 0, 1292) || !transport.remember("v6-peer", 0, 1392) {
		t.Fatal("remember failed")
	}
	if size, _ := transport.budget(raw, "v4-peer", 0); size != 1292 {
		t.Fatal(size)
	}
	if size, _ := transport.budget(raw, "v6-peer", 0); size != 1392 {
		t.Fatal(size)
	}
	transport.Reset()
	if transport.remember("v4-peer", 0, 1292) {
		t.Fatal("old connection contaminated new network")
	}
	if size, _ := transport.budget(raw, "v4-peer", 1); size != helloColdBudget {
		t.Fatal(size)
	}
	transport.remember("v4-peer", 1, 1292)
	clock = clock.Add(helloCacheTTL + time.Second)
	if size, _ := transport.budget(raw, "v4-peer", 1); size != helloColdBudget {
		t.Fatal("expired capacity reused", size)
	}
}

type helloAddressMemoryConn struct {
	*helloMemoryConn
	address *net.TCPAddr
}

func (c helloAddressMemoryConn) RemoteAddr() net.Addr { return c.address }

func TestHelloColdCapacityPreservesWholeApplicationRequest(t *testing.T) {
	for _, tc := range []struct {
		name, endpoint, source string
		initial, budget        int
	}{
		{"ipv6-default", "[2001:db8::1]:443", "cold_ipv6_estimate", 0, 1180},
		{"ipv4-measured", "192.0.2.1:443", "configured_initial_limit", 1200, 1200},
	} {
		for _, path := range []string{"write", "buffer", "vector"} {
			for _, reuse := range []bool{false, true} {
				t.Run(tc.name+"/"+path+map[bool]string{false: "/fresh", true: "/reuse"}[reuse], func(t *testing.T) {
					transport, err := NewHelloTransportWithOptions(helloTestPSK, HelloTransportOptions{InitialSYNDataLimit: tc.initial})
					if err != nil {
						t.Fatal(err)
					}
					var info HelloFrameInfo
					transport.OnFirstFrame = func(row HelloFrameInfo) { info = row }
					memory := new(helloMemoryConn)
					address, err := net.ResolveTCPAddr("tcp", tc.endpoint)
					if err != nil {
						t.Fatal(err)
					}
					physical := transport.Wrap(helloAddressMemoryConn{memory, address}, tc.endpoint)
					client, err := NewClient(ClientOptions{PSK: helloTestPSK, Reuse: reuse, Dialer: helloMemoryDialer{conn: physical}, Server: M.ParseSocksaddr(tc.endpoint)})
					if err != nil {
						t.Fatal(err)
					}
					defer client.Close()
					conn, err := client.DialContext(context.Background(), M.ParseSocksaddr("example.test:443"))
					if err != nil {
						t.Fatal(err)
					}
					want := bytes.Repeat([]byte{0x5c}, 512)
					if path == "write" {
						_, err = conn.Write(want)
					} else {
						front, rear := N.CalculateFrontHeadroom(conn), N.CalculateRearHeadroom(conn)
						parts := [][]byte{want}
						if path == "vector" {
							parts = [][]byte{want[:256], want[256:]}
						}
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
					if info.Budget != tc.budget || info.BudgetSource != tc.source || info.OriginalBytes != info.InitialWriteBytes || memory.writes != 1 {
						t.Fatal("cold request split or budget mislabeled", info, memory.writes)
					}
					wire := bytes.NewReader(memory.Bytes())
					prefix, err := transport.DecodeHello(wire)
					if err != nil || wire.Len() != 0 {
						t.Fatal("unframed suffix remains", err, wire.Len())
					}
					reader, record, err := readFirstRecord(bytes.NewReader(prefix), ModeDefault, helloTestPSK, NewProfile(helloTestPSK), N.ReadWaitOptions{})
					if err != nil {
						t.Fatal(err)
					}
					server, _ := NewService(ServerOptions{PSK: helloTestPSK})
					if _, err = server.readRequest(record); err != nil {
						record.Release()
						t.Fatal(err)
					}
					actual := append([]byte(nil), record.Bytes()...)
					record.Release()
					for len(actual) < len(want) {
						record, err = reader.ReadRecord()
						if err != nil {
							t.Fatal("first envelope omits application bytes", err, len(actual))
						}
						actual = append(actual, record.Bytes()...)
						record.Release()
					}
					if !bytes.Equal(actual, want) {
						t.Fatal("early application payload changed", len(actual))
					}
				})
			}
		}
	}
}

func TestHelloInitialLimitDoesNotOverrideObservation(t *testing.T) {
	for _, invalid := range []int{-1, helloMinBudget - 1, helloMaxBudget + 1} {
		if _, err := NewHelloTransportWithOptions(helloTestPSK, HelloTransportOptions{InitialSYNDataLimit: invalid}); err == nil {
			t.Fatal("invalid limit accepted", invalid)
		}
	}
	transport, _ := NewHelloTransportWithOptions(helloTestPSK, HelloTransportOptions{InitialSYNDataLimit: 1200})
	raw := new(helloMemoryConn)
	transport.remember("192.0.2.1:443", 0, 400)
	if n, source := transport.budget(raw, "192.0.2.1:443", 0); n != 400 || source != "observed_peer" {
		t.Fatal("ignored lower observed limit", n, source)
	}
	transport.Reset()
	if n, source := transport.budget(raw, "192.0.2.1:443", 1); n != 1200 || source != "configured_initial_limit" {
		t.Fatal("reset converted assumption into observation", n, source)
	}
	defaults, _ := NewHelloTransport(helloTestPSK)
	if n, source := defaults.initialBudget("[::ffff:192.0.2.1]:443"); n != 496 || source != "cold_estimate" {
		t.Fatal("mapped IPv4 treated as IPv6", n, source)
	}
}

type helloEchoHandler struct{}

func (helloEchoHandler) NewConnectionEx(_ context.Context, conn net.Conn, _, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	go func() {
		_, err := io.Copy(conn, conn)
		conn.Close()
		if onClose != nil {
			onClose(err)
		}
	}()
}
func (helloEchoHandler) NewPacketConnectionEx(_ context.Context, conn N.PacketConn, _, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	go func() {
		defer conn.Close()
		for {
			packet := buf.NewPacket()
			packet.Resize(N.CalculateFrontHeadroom(conn), 0)
			destination, err := conn.ReadPacket(packet)
			if err != nil {
				packet.Release()
				if onClose != nil {
					onClose(err)
				}
				return
			}
			if err = conn.WritePacket(packet, destination); err != nil {
				if onClose != nil {
					onClose(err)
				}
				return
			}
		}
	}()
}

type helloDecodedConn struct {
	net.Conn
	reader io.Reader
}

func (c *helloDecodedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

type helloTestDialer struct {
	endpoint string
	count    atomic.Int32
}

type helloMemoryDialer struct {
	N.Dialer
	conn net.Conn
}

type helloVectorMemoryConn struct{ *helloMemoryConn }

func (c helloVectorMemoryConn) WriteVectorised(buffers []*buf.Buffer) error {
	defer buf.ReleaseMulti(buffers)
	for _, b := range buffers {
		if _, err := c.Write(b.Bytes()); err != nil {
			return err
		}
	}
	return nil
}

func (d helloMemoryDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return d.conn, nil
}

func TestHelloFirstApplicationVectorFitsOneRecord(t *testing.T) {
	for _, reuse := range []bool{false, true} {
		for _, framed := range []bool{false, true} {
			for _, size := range []int{128, 400} {
				raw := new(helloMemoryConn)
				transport, _ := NewHelloTransport(helloTestPSK)
				// Preserve the normal vector capability, as a TCP socket would.
				// Otherwise bufio's fallback joins the batch before Snell sees it.
				var physical net.Conn = helloVectorMemoryConn{raw}
				if framed {
					physical = transport.Wrap(physical, "test")
				}
				client, err := NewClient(ClientOptions{PSK: helloTestPSK, Reuse: reuse, Dialer: helloMemoryDialer{conn: physical}, Server: M.ParseSocksaddr("192.0.2.1:443")})
				if err != nil {
					t.Fatal(err)
				}
				conn, err := client.DialContext(context.Background(), M.ParseSocksaddr("example.test:443"))
				if err != nil {
					t.Fatal(err)
				}
				want := bytes.Repeat([]byte{0x5a}, size)
				front, rear := N.CalculateFrontHeadroom(conn), N.CalculateRearHeadroom(conn)
				var buffers []*buf.Buffer
				for _, p := range [][]byte{nil, want[:size/2], nil, want[size/2:]} {
					b := buf.NewSize(front + len(p) + rear)
					b.Resize(front, 0)
					_, _ = b.Write(p)
					buffers = append(buffers, b)
				}
				if err = bufio.NewVectorisedWriter(conn).WriteVectorised(buffers); err != nil {
					t.Fatal(err)
				}
				reader := bytes.NewReader(append([]byte(nil), raw.Bytes()...))
				var wire io.Reader = reader
				if framed {
					prefix, err := transport.DecodeHello(reader)
					if err != nil {
						t.Fatal(err)
					}
					wire = io.MultiReader(bytes.NewReader(prefix), reader)
				}
				_, record, err := readFirstRecord(wire, ModeDefault, helloTestPSK, NewProfile(helloTestPSK), N.ReadWaitOptions{})
				if err != nil {
					t.Fatal(err)
				}
				server, _ := NewService(ServerOptions{PSK: helloTestPSK})
				if _, err = server.readRequest(record); err != nil {
					t.Fatal(err)
				}
				early := size / 2
				if framed && size == 128 {
					early = size
				}
				if !bytes.Equal(record.Bytes(), want[:early]) {
					t.Fatalf("reuse=%v framed=%v size=%d first application bytes=%d want=%d", reuse, framed, size, record.Len(), early)
				}
				record.Release()
				client.Close()
			}
		}
	}
}

func (d *helloTestDialer) DialContext(ctx context.Context, network string, _ M.Socksaddr) (net.Conn, error) {
	d.count.Add(1)
	return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, d.endpoint)
}
func (d *helloTestDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unexpected UDP socket")
}

func newHelloTestServer(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	transport, _ := NewHelloTransport(helloTestPSK)
	service, err := NewService(ServerOptions{PSK: helloTestPSK, Handler: helloEchoHandler{}})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var count atomic.Int32
	var workers sync.WaitGroup
	var connectionMu sync.Mutex
	var connections []net.Conn
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			count.Add(1)
			connectionMu.Lock()
			connections = append(connections, conn)
			connectionMu.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				prefix, err := transport.DecodeHello(conn)
				if err != nil {
					conn.Close()
					return
				}
				decoded := &helloDecodedConn{Conn: conn, reader: io.MultiReader(bytes.NewReader(prefix), conn)}
				_ = service.NewConnection(ctx, decoded, M.Socksaddr{}, func(error) { conn.Close() })
			}()
		}
	}()
	t.Cleanup(func() {
		cancel()
		listener.Close()
		connectionMu.Lock()
		for _, conn := range connections {
			conn.Close()
		}
		connectionMu.Unlock()
		workers.Wait()
	})
	return listener.Addr().String(), &count
}

func TestHelloActualClientFreshAndSequentialReuse(t *testing.T) {
	for _, reuse := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "reuse"}[reuse], func(t *testing.T) {
			endpoint, accepted := newHelloTestServer(t)
			transport, _ := NewHelloTransport(helloTestPSK)
			var frames atomic.Int32
			transport.OnFirstFrame = func(HelloFrameInfo) { frames.Add(1) }
			dialer := &helloTestDialer{endpoint: endpoint}
			client, err := NewClient(ClientOptions{PSK: helloTestPSK, Reuse: reuse, Dialer: transport.WrapDialer(dialer), Server: M.ParseSocksaddr(endpoint)})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			for index, path := range []string{"write", "buffer", "vector"} {
				conn, err := client.DialContext(context.Background(), M.ParseSocksaddr("example.test:443"))
				if err != nil {
					t.Fatal(err)
				}
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				want := bytes.Repeat([]byte{byte(index + 1)}, 7000+index)
				makeBuffer := func(p []byte) *buf.Buffer {
					b := buf.NewSize(len(p) + 8192)
					b.Resize(4096, 0)
					_, _ = b.Write(p)
					return b
				}
				switch path {
				case "write":
					_, err = conn.Write(want)
				case "buffer":
					err = conn.(interface{ WriteBuffer(*buf.Buffer) error }).WriteBuffer(makeBuffer(want))
				case "vector":
					err = bufio.NewVectorisedWriter(conn).WriteVectorised([]*buf.Buffer{makeBuffer(want[:3000]), makeBuffer(want[3000:])})
				}
				if err != nil {
					t.Fatal(path, err)
				}
				got := make([]byte, len(want))
				if _, err = io.ReadFull(conn, got); err != nil {
					t.Fatal(path, err)
				}
				if !bytes.Equal(got, want) {
					t.Fatal("decrypted payload differs", path)
				}
				if err = conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
					t.Fatal(err)
				}
				if _, err = io.Copy(io.Discard, conn); err != nil {
					t.Fatal(err)
				}
				if err = conn.Close(); err != nil {
					t.Fatal(err)
				}
			}
			want := int32(3)
			if reuse {
				want = 1
			}
			if dialer.count.Load() != want || accepted.Load() != want || frames.Load() != want {
				t.Fatal("unexpected physical connection/framing count", dialer.count.Load(), accepted.Load(), frames.Load())
			}
		})
	}
}

func TestHelloActualClientUDPTunnel(t *testing.T) {
	endpoint, _ := newHelloTestServer(t)
	transport, _ := NewHelloTransport(helloTestPSK)
	dialer := transport.WrapDialer(&helloTestDialer{endpoint: endpoint})
	raw, err := dialer.DialContext(context.Background(), "tcp", M.ParseSocksaddr(endpoint))
	if err != nil {
		t.Fatal(err)
	}
	raw.SetDeadline(time.Now().Add(3 * time.Second))
	client, _ := NewClient(ClientOptions{PSK: helloTestPSK})
	packetConn, err := client.DialPacketConn(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer packetConn.Close()
	destination := M.ParseSocksaddr("192.0.2.2:1234")
	for _, size := range []int{7, 512, 1300} {
		want := bytes.Repeat([]byte{byte(size)}, size)
		packet := buf.NewPacket()
		packet.Resize(N.CalculateFrontHeadroom(packetConn), 0)
		_, _ = packet.Write(want)
		if err = packetConn.WritePacket(packet, destination); err != nil {
			t.Fatal(err)
		}
		got := buf.NewPacket()
		actual, err := packetConn.ReadPacket(got)
		if err != nil {
			got.Release()
			t.Fatal(err)
		}
		if actual != destination || !bytes.Equal(got.Bytes(), want) {
			got.Release()
			t.Fatal("UDP payload or destination differs")
		}
		got.Release()
	}
}

func TestHelloOldGenerationCompletesObservationWithoutCaching(t *testing.T) {
	endpoint, _ := newHelloTestServer(t)
	raw, err := net.DialTimeout("tcp", endpoint, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(3 * time.Second))
	transport, _ := NewHelloTransport(helloTestPSK)
	physical := transport.Wrap(raw, endpoint).(*helloConn)
	transport.Reset()
	client, _ := NewClient(ClientOptions{PSK: helloTestPSK})
	defer client.Close()
	proxy := client.DialEarlyConn(physical, M.ParseSocksaddr("example.test:443"))
	want := []byte("request created before network change")
	if _, err = proxy.Write(want); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err = io.ReadFull(proxy, got); err != nil || !bytes.Equal(want, got) {
		t.Fatal(err)
	}
	if !physical.ReaderReplaceable() {
		t.Fatal("old generation would repeat TCP_INFO on every read")
	}
	transport.mu.Lock()
	entries := len(transport.capacities)
	transport.mu.Unlock()
	if entries != 0 {
		t.Fatal("old connection repopulated new network cache", entries)
	}
}
