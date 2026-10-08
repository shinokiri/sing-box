package snellv6

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/internal/reuse"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func httpFixture(t testing.TB) ([]byte, *HTTPFraming) {
	t.Helper()
	for i := 0; i < 100; i++ {
		psk := []byte(fmt.Sprintf("public HTTP framing fixture %d", i))
		if framing, err := NewHTTPFraming(psk); err == nil {
			return psk, framing
		}
	}
	t.Fatal("no compatible public fixture")
	return nil, nil
}

func TestHTTPFramingRestoresActualCiphertext(t *testing.T) {
	compatible := 0
	for i := 0; i < 24; i++ {
		psk := []byte(fmt.Sprintf("public HTTP framing fixture %d", i))
		framing, err := NewHTTPFraming(psk)
		if err != nil {
			continue
		}
		compatible++
		for _, size := range []int{16, 512, 2048, 32768} {
			original, _ := receiveWire(t, psk, [][]byte{bytes.Repeat([]byte{0xa7}, size)})
			before := bytes.Clone(original)
			wire, err := framing.Encode(original)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, original) {
				t.Fatal("Encode modified caller memory")
			}
			if len(wire) > len(original) {
				t.Fatal("early capacity reduced")
			}
			header := bytes.Index(wire, []byte("\r\n\r\n")) + 4
			for _, budget := range []int{header + saltLen, 1292, 1392, len(wire)} {
				if budget > len(wire) {
					continue
				}
				reader := bytes.NewReader(wire[:budget])
				prefix, err := framing.DecodePrefix(reader)
				if err != nil {
					t.Fatal(err)
				}
				tail, _ := io.ReadAll(reader)
				restored := append(prefix, tail...)
				if len(restored) < budget || !bytes.Equal(restored, original[:len(restored)]) {
					t.Fatal("early ciphertext was changed or deferred")
				}
			}
			for n := range framing.template {
				if !framing.variable[n] {
					before[n] ^= 1
					if _, err := framing.Encode(before); err == nil {
						t.Fatal("changed deterministic prefix accepted")
					}
					break
				}
			}
		}
	}
	if compatible == 0 {
		t.Fatal("no tested profiles")
	}
}

func TestHTTPFramingStreamsBeforeBodyArrives(t *testing.T) {
	psk, framing := httpFixture(t)
	original, _ := receiveWire(t, psk, [][]byte{bytes.Repeat([]byte{0x91}, 32768)})
	wire, err := framing.Encode(original)
	if err != nil {
		t.Fatal(err)
	}
	prefixEnd := bytes.Index(wire, []byte("\r\n\r\n")) + 4 + saltLen
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	server.SetDeadline(time.Now().Add(3 * time.Second))
	done := make(chan error, 1)
	go func() {
		prefix, err := framing.DecodePrefix(server)
		if err == nil && !bytes.Equal(prefix, original[:len(prefix)]) {
			err = errors.New("prefix mismatch")
		}
		done <- err
	}()
	if _, err = client.Write(wire[:prefixEnd]); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("decoder waited for remaining body")
	}
}

func TestHTTPFramingRejectsMalformedHeaders(t *testing.T) {
	_, framing := httpFixture(t)
	for _, body := range []string{"", "-1\r\n\r\n", "15\r\n\r\n", "99999999999999999999\r\n\r\n", "9223372036854775808\r\n\r\n", "16\r\nX\n", "16\r\n\r\nshort"} {
		if _, err := framing.DecodePrefix(strings.NewReader(httpFramingPrefix + body)); err == nil {
			t.Fatalf("accepted malformed %q", body)
		}
	}
	for _, mode := range []Mode{ModeUnshaped, ModeUnsafeRaw} {
		if _, err := NewClient(ClientOptions{PSK: []byte("public mode fixture"), Mode: mode, HTTPFraming: true}); err == nil {
			t.Fatal("unsupported mode accepted")
		}
	}
}

type httpCaptureConn struct {
	net.Conn
	wire         bytes.Buffer
	reply        *bytes.Reader
	writes       int
	vectorWrites int
}

func (c *httpCaptureConn) Write(p []byte) (int, error) { c.writes++; return c.wire.Write(p) }
func (c *httpCaptureConn) Read(p []byte) (int, error) {
	if c.reply == nil {
		return 0, io.EOF
	}
	return c.reply.Read(p)
}
func (c *httpCaptureConn) Close() error                                       { return nil }
func (c *httpCaptureConn) CreateVectorisedWriter() (N.VectorisedWriter, bool) { return c, true }
func (c *httpCaptureConn) WriteVectorised(buffers []*buf.Buffer) error {
	defer buf.ReleaseMulti(buffers)
	c.vectorWrites++
	for _, buffer := range buffers {
		c.wire.Write(buffer.Bytes())
	}
	return nil
}
func httpWriteBuffer(payload []byte) *buf.Buffer {
	buffer := buf.NewSize(len(payload) + 8192)
	buffer.Resize(4096, 0)
	buffer.Write(payload)
	return buffer
}

func TestHTTPFramingTCPPathsRetainVectorWriter(t *testing.T) {
	psk, framing := httpFixture(t)
	for _, reused := range []bool{false, true} {
		for _, writeMode := range []string{"slice", "buffer", "vector"} {
			t.Run(fmt.Sprintf("reuse=%v/%s", reused, writeMode), func(t *testing.T) {
				client, err := NewClient(ClientOptions{PSK: psk, HTTPFraming: true, Reuse: reused})
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				raw := new(httpCaptureConn)
				destination := M.ParseSocksaddr("127.0.0.1:853")
				var conn net.Conn
				var session *reuseSession
				if reused {
					session = client.newReuseSession(raw)
					session.state.Store(uint32(reuse.StateActive))
					conn, err = session.DialConn(destination)
				} else {
					conn = client.DialEarlyConn(raw, destination)
				}
				if err != nil {
					t.Fatal(err)
				}
				payload := bytes.Repeat([]byte{0x37}, 2048)
				switch writeMode {
				case "slice":
					_, err = conn.Write(payload)
				case "buffer":
					err = conn.(N.ExtendedWriter).WriteBuffer(httpWriteBuffer(payload))
				case "vector":
					writer, ok := conn.(N.VectorisedWriteCreator).CreateVectorisedWriter()
					if !ok {
						t.Fatal("lost vector writer before handshake")
					}
					err = writer.WriteVectorised([]*buf.Buffer{httpWriteBuffer(payload[:1024]), httpWriteBuffer(payload[1024:])})
				}
				if err != nil {
					t.Fatal(err)
				}
				firstWireEnd := raw.wire.Len()
				writer, ok := conn.(N.VectorisedWriteCreator).CreateVectorisedWriter()
				if !ok {
					t.Fatal("lost vector writer after handshake")
				}
				tail := bytes.Repeat([]byte{0x81}, 1024)
				if err = writer.WriteVectorised([]*buf.Buffer{httpWriteBuffer(tail)}); err != nil {
					t.Fatal(err)
				}
				if raw.vectorWrites == 0 {
					t.Fatal("subsequent vector write did not reach original transport")
				}
				var recordWriter reuse.RecordWriter
				if reused {
					recordWriter = session.writer
				} else {
					recordWriter = conn.(*clientConn).writer
				}
				if recordWriter.(*shapedWriter).upstream != raw {
					t.Fatal("first-write wrapper retained on fast path")
				}
				if bytes.Contains(raw.wire.Bytes()[firstWireEnd:], []byte(httpFramingPrefix)) {
					t.Fatal("HTTP header repeated")
				}
				reader := bytes.NewReader(raw.wire.Bytes())
				prefix, err := framing.DecodePrefix(reader)
				if err != nil {
					t.Fatal(err)
				}
				records := newShapedReader(io.MultiReader(bytes.NewReader(prefix), reader), psk, client.profile)
				request := snell.Request{Command: snell.CommandConnectV2, Destination: destination}
				expected := buf.NewSize(request.Len() + len(payload) + len(tail))
				defer expected.Release()
				if err = request.Write(expected); err != nil {
					t.Fatal(err)
				}
				expected.Write(payload)
				expected.Write(tail)
				actual := make([]byte, expected.Len())
				if _, err = io.ReadFull(records, actual); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(actual, expected.Bytes()) {
					t.Fatal("decrypted request or body differs")
				}
			})
		}
	}
}

func TestHTTPFramingUDPRequest(t *testing.T) {
	psk, framing := httpFixture(t)
	client, err := NewClient(ClientOptions{PSK: psk, HTTPFraming: true})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	reply, _ := receiveWire(t, psk, [][]byte{{0}})
	raw := &httpCaptureConn{reply: bytes.NewReader(reply)}
	packet, err := client.DialPacketConn(raw)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x45}, 128)
	if err = packet.WritePacket(httpWriteBuffer(payload), M.ParseSocksaddr("127.0.0.1:53")); err != nil {
		t.Fatal(err)
	}
	reader := bytes.NewReader(raw.wire.Bytes())
	prefix, err := framing.DecodePrefix(reader)
	if err != nil {
		t.Fatal(err)
	}
	records := newShapedReader(io.MultiReader(bytes.NewReader(prefix), reader), psk, client.profile)
	request, err := records.ReadRecord()
	if err != nil {
		t.Fatal(err)
	}
	defer request.Release()
	if len(request.Bytes()) < 3 || request.Bytes()[1] != snell.CommandUDP {
		t.Fatal("incorrect UDP tunnel request")
	}
	datagram, err := records.ReadRecord()
	if err != nil {
		t.Fatal(err)
	}
	defer datagram.Release()
	if !bytes.HasSuffix(datagram.Bytes(), payload) {
		t.Fatal("UDP payload mismatch")
	}
}
