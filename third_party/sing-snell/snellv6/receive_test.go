package snellv6

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/internal/reuse"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func receiveWire(t testing.TB, psk []byte, payloads [][]byte) ([]byte, *Profile) {
	t.Helper()
	salt := bytes.Repeat([]byte{0x35}, snell.SaltLen)
	aead, err := snell.NewAEAD(snell.DeriveKey(psk, salt))
	if err != nil { t.Fatal(err) }
	profile := NewProfile(psk)
	w := newShapedWriter(io.Discard, profile, salt, aead, make([]byte, snell.NonceLen))
	var wire []byte
	for _, payload := range payloads {
		record := w.makeSliceRecord(payload)
		wire = append(wire, record.Bytes()...)
		record.Release()
	}
	return wire, profile
}

func TestBufferedResponseRetainedHeadroomAndReuse(t *testing.T) {
	for profileID := range 8 {
		for _, room := range []int{0, 32, 72, 256} {
			t.Run(fmt.Sprintf("profile%d/room%d", profileID, room), func(t *testing.T) {
				psk := []byte(fmt.Sprintf("public receive fixture %d", profileID))
				var payloads [][]byte
				for i := range 80 {
					size := []int{64, 1440, 16384, 65535, 7}[i%5]
					payloads = append(payloads, bytes.Repeat([]byte{byte(i)}, size))
					if i%10 == 9 { payloads = append(payloads, nil) }
				}
				wire, profile := receiveWire(t, psk, payloads)
				r := newBufferedShapedReader(bytes.NewReader(wire), psk, profile)
				defer r.releaseReceive()
				r.InitializeReadWaiter(N.ReadWaitOptions{FrontHeadroom: room, RearHeadroom: room/2})
				var held []*buf.Buffer
				var wants [][]byte
				for _, want := range payloads {
					body, err := r.WaitReadBuffer()
					if want == nil {
						if !errors.Is(err, io.EOF) { t.Fatal(err) }
						continue
					}
					if err != nil { t.Fatal(err) }
					if !bytes.Equal(body.Bytes(), want) { t.Fatal("payload mismatch") }
					if body.Start() < room || body.FreeLen() < room/2 { t.Fatal("missing writable room") }
					clear(body.ExtendHeader(room))
					body.Advance(room)
					clear(body.Extend(room/2))
					body.Truncate(len(want))
					held = append(held, body)
					wants = append(wants, want)
				}
				r.releaseReceive()
				if r.block != nil || r.cache != nil { t.Fatal("reader retained memory after close") }
				var wg sync.WaitGroup
				for i, body := range held {
					if !bytes.Equal(body.Bytes(), wants[i]) { t.Fatal("a later read or close changed held data") }
					wg.Add(1)
					go func() { defer wg.Done(); body.Release() }()
				}
				wg.Wait()
			})
		}
	}
}

func TestResponseLifecycleCloseRace(t *testing.T) {
	for range 256 {
		var life receiveLifecycle
		var released atomic.Int32
		release := func() { released.Add(1) }
		start := make(chan struct{})
		var wg sync.WaitGroup
		for range 4 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if life.begin() { life.end(release) }
			}()
		}
		for range 2 {
			wg.Add(1)
			go func() { defer wg.Done(); <-start; life.close(release) }()
		}
		close(start)
		wg.Wait()
		if released.Load() != 1 || life.begin() { t.Fatal("close did not release exactly once or accepted a late read") }
	}
}

type receiveNotifyConn struct { net.Conn; reads chan struct{} }
func (c *receiveNotifyConn) Read(p []byte) (int, error) {
	select { case c.reads <- struct{}{}: default: }
	return c.Conn.Read(p)
}

func receiveAwait(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select { case <-signal: case <-time.After(3*time.Second): t.Fatal("read never started") }
}

func TestResponseCloseDuringRead(t *testing.T) {
	for _, reused := range []bool{false, true} {
		for _, firstReply := range []bool{false, true} {
			t.Run(fmt.Sprintf("reuse%v/reply%v", reused, firstReply), func(t *testing.T) {
				psk := []byte("public close lifetime fixture")
				client, err := NewClient(ClientOptions{PSK: psk, Reuse: reused})
				if err != nil { t.Fatal(err) }
				defer client.Close()
				source, sink := net.Pipe()
				defer sink.Close()
				raw := &receiveNotifyConn{Conn: source, reads: make(chan struct{}, 8)}
				var waiter N.ReadWaiter
				var physical io.Closer
				var reader func() reuse.RecordReader
				if reused {
					session := client.newReuseSession(raw)
					session.state.Store(uint32(reuse.StateActive))
					conn, err := session.DialConn(M.Socksaddr{})
					if err != nil { t.Fatal(err) }
					waiter = &reuseReadWaiter{conn: conn.(*reuseConn)}
					physical = session
					reader = func() reuse.RecordReader { return session.reader }
				} else {
					conn := client.DialEarlyConn(raw, M.Socksaddr{}).(*clientConn)
					waiter, physical = conn, conn
					reader = func() reuse.RecordReader { return conn.reader }
				}
				defer physical.Close()
				waiter.InitializeReadWaiter(N.ReadWaitOptions{FrontHeadroom: 72})
				want := bytes.Repeat([]byte{0x67}, 65534)
				var held *buf.Buffer
				if firstReply {
					payload := append([]byte{snell.ReplyTunnel}, want...)
					wire, _ := receiveWire(t, psk, [][]byte{payload})
					go func() { _, _ = sink.Write(wire) }()
					held, err = waiter.WaitReadBuffer()
					if err != nil { t.Fatal(err) }
					defer held.Release()
					for len(raw.reads) > 0 { <-raw.reads }
				}
				done := make(chan error, 1)
				go func() { body, err := waiter.WaitReadBuffer(); if body != nil { body.Release() }; done <- err }()
				receiveAwait(t, raw.reads)
				physical.Close()
				select {
				case err := <-done: if err == nil { t.Fatal("closed transport returned a record") }
				case <-time.After(3*time.Second): t.Fatal("close did not unblock read")
				}
				if r, ok := reader().(*bufferedShapedReader); ok && (r.block != nil || r.cache != nil) { t.Fatal("close retained receive storage") }
				if held != nil && !bytes.Equal(held.Bytes(), want) { t.Fatal("close invalidated returned payload") }
				if _, err := waiter.WaitReadBuffer(); !errors.Is(err, net.ErrClosed) { t.Fatalf("late read: %v", err) }
			})
		}
	}
}

type receiveMemoryConn struct { io.Reader }
func (*receiveMemoryConn) Write(p []byte) (int, error) { return len(p), nil }
func (*receiveMemoryConn) Close() error { return nil }
func (*receiveMemoryConn) LocalAddr() net.Addr { return &net.TCPAddr{} }
func (*receiveMemoryConn) RemoteAddr() net.Addr { return &net.TCPAddr{} }
func (*receiveMemoryConn) SetDeadline(time.Time) error { return nil }
func (*receiveMemoryConn) SetReadDeadline(time.Time) error { return nil }
func (*receiveMemoryConn) SetWriteDeadline(time.Time) error { return nil }

func TestResponseSessionReusesPrefetchedReply(t *testing.T) {
	psk := []byte("public reused response fixture")
	client, err := NewClient(ClientOptions{PSK: psk, Reuse: true})
	if err != nil { t.Fatal(err) }
	defer client.Close()
	wire, _ := receiveWire(t, psk, [][]byte{{snell.ReplyTunnel, 1}, nil, {snell.ReplyTunnel, 2}, nil})
	session := client.newReuseSession(&receiveMemoryConn{Reader: bytes.NewReader(wire)})
	session.state.Store(uint32(reuse.StateActive))
	defer session.Close()
	var held []*buf.Buffer
	defer func() { buf.ReleaseMulti(held) }()
	for _, expected := range []byte{1, 2} {
		conn, err := session.DialConn(M.Socksaddr{})
		if err != nil { t.Fatal(err) }
		w := &reuseReadWaiter{conn: conn.(*reuseConn)}
		w.InitializeReadWaiter(N.ReadWaitOptions{FrontHeadroom: 72})
		body, err := w.WaitReadBuffer()
		if err != nil || body.Len() != 1 || body.Byte(0) != expected { t.Fatalf("reply %d: %v", expected, err) }
		held = append(held, body)
		if _, err := w.WaitReadBuffer(); !errors.Is(err, io.EOF) { t.Fatal(err) }
		if err := conn.Close(); err != nil { t.Fatal(err) }
		if expected == 1 {
			next, found, closed := client.pool.Take()
			if next != session || !found || closed { t.Fatal("session was not returned for reuse") }
		}
	}
	session.Close()
	for i, body := range held { if body.Byte(0) != byte(i+1) { t.Fatal("reuse changed an older payload") } }
}

func TestBufferedResponseEOFAndNoProgress(t *testing.T) {
	psk := []byte("public response EOF fixture")
	wire, profile := receiveWire(t, psk, [][]byte{[]byte("one"), nil, []byte("two"), nil})
	r := newBufferedShapedReader(&receiveDataEOF{wire}, psk, profile)
	defer r.releaseReceive()
	for _, want := range [][]byte{[]byte("one"), nil, []byte("two"), nil} {
		body, err := r.ReadRecord()
		if want == nil { if !errors.Is(err, io.EOF) { t.Fatal(err) }; continue }
		if err != nil || !bytes.Equal(body.Bytes(), want) { t.Fatalf("data with EOF: %v", err) }
		body.Release()
	}
	if r.block != nil { t.Fatal("drained EOF retained storage") }
	stalled := newBufferedShapedReader(receiveNoProgress{}, psk, profile)
	defer stalled.releaseReceive()
	if _, err := stalled.ReadRecord(); !errors.Is(err, io.ErrNoProgress) { t.Fatal(err) }
}

type receiveDataEOF struct { data []byte }
func (r *receiveDataEOF) Read(p []byte) (int, error) {
	n := copy(p, r.data); r.data = r.data[n:]
	if len(r.data) == 0 { return n, io.EOF }
	return n, nil
}
type receiveNoProgress struct{}
func (receiveNoProgress) Read([]byte) (int, error) { return 0, nil }
