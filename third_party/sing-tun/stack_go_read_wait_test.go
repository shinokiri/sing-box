package tun

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// This fixture uses the real receive store and read/consumption paths, without
// starting an engine or a TCP peer. Kernel tests cover ACK/window interaction.
func newGoReadWaitFixture(t testing.TB, payload []byte) *GoConn {
	t.Helper()
	engine := &goEngine{slabPool: newGoSlabPool(nil, 8)}
	conn := new(GoConn)
	conn.initialize(engine, flowKey{}, M.Socksaddr{}, M.Socksaddr{})
	conn.phase = goPhaseEstablished
	conn.state = goTCPEstablished
	conn.receiveCapacity = goReceiveCapacityMax
	conn.receiveNext = 1
	conn.consumedTail.Store(1)
	conn.receiveAvailable.Store(1)
	conn.windowUpdateAt.Store(math.MaxUint64)
	if len(payload) > 0 {
		engine.deliverInOrder(conn, payload)
	}
	t.Cleanup(func() {
		conn.receiveChain.releaseAll()
		engine.slabPool.close()
		engine.releaseControlQueue()
	})
	return conn
}

func TestGoReadWaitBatchReady(t *testing.T) {
	for _, batchSize := range []int{-1, 0, 1, 2, 8, 100} {
		t.Run(fmt.Sprint(batchSize), func(t *testing.T) {
			options := N.ReadWaitOptions{FrontHeadroom: 91, RearHeadroom: 73, MTU: 10000, IncreaseBuffer: true, BatchSize: batchSize}
			probe := options.NewBuffer()
			capacity := probe.FreeLen()
			probe.Release()
			payload := make([]byte, 13*capacity+7)
			for i := range payload {
				payload[i] = byte(i*37 + i/251)
			}
			conn := newGoReadWaitFixture(t, payload)
			conn.finReceived = true
			// A dead but drainable connection must still return all queued bytes.
			conn.dead, conn.drainable = true, true
			waiter, ok := bufio.CreateVectorisedReadWaiter(conn)
			if !ok || waiter.InitializeReadWaiter(options) {
				t.Fatal("vector waiter unavailable or unexpectedly requires copying")
			}
			var owned []*buf.Buffer
			defer func() { buf.ReleaseMulti(owned) }()
			remaining := len(payload)
			limit := max(1, min(batchSize, goMaxReadBatch))
			for remaining > 0 {
				buffers, err := waiter.WaitReadBuffers()
				if err != nil {
					t.Fatal(err)
				}
				wantCount := min(limit, (remaining+capacity-1)/capacity)
				if len(buffers) != wantCount {
					t.Fatalf("got %d buffers, want %d", len(buffers), wantCount)
				}
				for _, buffer := range buffers {
					if buffer.Start() != 91 || buffer.FreeLen() < 73 || buffer.Len() == 0 {
						t.Fatal("invalid headroom, tailroom, or empty buffer")
					}
					remaining -= buffer.Len()
				}
				owned = append(owned, buffers...)
			}
			if conn.consumedTail.Load() != uint64(len(payload)+1) || !conn.windowMessage.queued.Load() {
				t.Fatal("consumption or window notification lost")
			}
			buffers, err := waiter.WaitReadBuffers()
			if len(buffers) != 0 || !errors.Is(err, io.EOF) {
				t.Fatalf("after drain: %d buffers, %v", len(buffers), err)
			}
			conn.receiveChain.releaseAll()
			// Returned buffers must outlive both another read and the receive store.
			if !bytes.Equal(bytes.Join(buf.ToSliceMulti(owned), nil), payload) {
				t.Fatal("payload reordered or returned buffers invalidated")
			}
		})
	}
}

func TestGoReadWaitBatchNoFillWait(t *testing.T) {
	for _, parked := range []bool{false, true} {
		t.Run(fmt.Sprintf("parked=%v", parked), func(t *testing.T) {
			conn := newGoReadWaitFixture(t, nil)
			waiter, _ := conn.CreateVectorisedReadWaiter()
			waiter.InitializeReadWaiter(N.ReadWaitOptions{MTU: 1000, BatchSize: 8})
			payload := bytes.Repeat([]byte{42}, 64)
			if !parked {
				conn.engine.deliverInOrder(conn, payload)
			}
			result := make(chan error, 1)
			go func() {
				buffers, err := waiter.WaitReadBuffers()
				defer buf.ReleaseMulti(buffers)
				if err == nil && (len(buffers) != 1 || !bytes.Equal(buffers[0].Bytes(), payload)) {
					err = errors.New("first ready message was changed or split")
				}
				result <- err
			}()
			if parked {
				deadline := time.Now().Add(time.Second)
				for !conn.readerParked.Load() && time.Now().Before(deadline) {
					runtime.Gosched()
				}
				if !conn.readerParked.Load() {
					conn.SetReadDeadline(time.Now())
					<-result
					t.Fatal("reader did not park")
				}
				conn.engine.deliverInOrder(conn, payload)
			}
			select {
			case err := <-result:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				conn.SetReadDeadline(time.Now())
				<-result
				t.Fatal("reader waited for more data after the first message")
			}
		})
	}
}

func TestGoReadWaitBatchErrors(t *testing.T) {
	for _, scenario := range []string{"deadline", "close", "reset", "eof"} {
		t.Run(scenario, func(t *testing.T) {
			conn := newGoReadWaitFixture(t, nil)
			waiter, _ := conn.CreateVectorisedReadWaiter()
			waiter.InitializeReadWaiter(N.ReadWaitOptions{BatchSize: 8})
			var want error
			switch scenario {
			case "deadline":
				conn.SetReadDeadline(time.Now().Add(-time.Second))
				want = os.ErrDeadlineExceeded
			case "close":
				conn.Close()
				want = net.ErrClosed
			case "reset":
				conn.err = errGoReset
				want = errGoReset
			case "eof":
				conn.finReceived = true
				want = io.EOF
			}
			buffers, err := waiter.WaitReadBuffers()
			if len(buffers) != 0 || !errors.Is(err, want) || conn.receiveTarget.buffer != nil {
				buf.ReleaseMulti(buffers)
				t.Fatalf("got %d buffers, err=%v, want %v", len(buffers), err, want)
			}
			if scenario == "deadline" {
				conn.SetReadDeadline(time.Time{})
				conn.engine.deliverInOrder(conn, []byte("after deadline reset"))
				buffers, err = waiter.WaitReadBuffers()
				defer buf.ReleaseMulti(buffers)
				if err != nil || len(buffers) != 1 || string(buffers[0].Bytes()) != "after deadline reset" {
					t.Fatal("reader did not recover after deadline reset:", err)
				}
			}
		})
	}
}

type goReadWaitRecorder struct {
	bytes.Buffer
	singleBytes int
	batchCount int
	largestBatch int
}

func (w *goReadWaitRecorder) WriterMTU() int { return 14000 }

func (w *goReadWaitRecorder) WriteBuffer(buffer *buf.Buffer) error {
	defer buffer.Release()
	w.singleBytes += buffer.Len()
	_, err := w.Write(buffer.Bytes())
	return err
}

func (w *goReadWaitRecorder) WriteVectorised(buffers []*buf.Buffer) error {
	defer buf.ReleaseMulti(buffers)
	if w.singleBytes < bufio.DefaultIncreaseBufferAfter {
		return errors.New("vector copy activated before the existing bulk threshold")
	}
	w.batchCount++
	w.largestBatch = max(w.largestBatch, len(buffers))
	for _, buffer := range buffers {
		if _, err := w.Write(buffer.Bytes()); err != nil {
			return err
		}
	}
	return nil
}

func TestGoReadWaitBatchCopyTransition(t *testing.T) {
	payload := bytes.Repeat([]byte("upload copy transition fixture "), 40000)
	conn := newGoReadWaitFixture(t, payload)
	conn.finReceived = true
	writer := new(goReadWaitRecorder)
	n, err := bufio.Copy(writer, conn)
	if err != nil || n != int64(len(payload)) || !bytes.Equal(writer.Bytes(), payload) {
		t.Fatalf("copy lost data: n=%d err=%v", n, err)
	}
	if writer.batchCount == 0 || writer.largestBatch != goMaxReadBatch {
		t.Fatalf("public copy did not use ready batches: calls=%d largest=%d", writer.batchCount, writer.largestBatch)
	}
}
