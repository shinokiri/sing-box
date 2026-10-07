//go:build shared_receive_study

package snellv6

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"
)

func sharedWire(t testing.TB, psk []byte, payloads [][]byte) ([]byte, *Profile) {
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

func TestStudySharedRetainedViewsAndHeadroom(t *testing.T) {
	for _, policy := range []string{"shared", "bounded", "detached"} {
	for profileID := range 8 {
		for _, room := range []int{0, 32, 72, 256} {
			t.Run(fmt.Sprintf("%s/profile%d/room%d", policy, profileID, room), func(t *testing.T) {
				psk := []byte(fmt.Sprintf("public shared receive fixture %d", profileID))
				var payloads [][]byte
				for i := range 80 {
					size := []int{64, 1440, 16384, 65535, 7}[i%5]
					payloads = append(payloads, bytes.Repeat([]byte{byte(i)}, size))
					if i%10 == 9 { payloads = append(payloads, nil) }
				}
				wire, profile := sharedWire(t, psk, payloads)
				beforeBytes, beforeBlocks := buf.StudySharedStorage()
				r := newSharedShapedReader(bytes.NewReader(wire), psk, profile)
				if policy != "shared" { r.enableBounded() }
				r.detached = policy == "detached"
				r.InitializeReadWaiter(N.ReadWaitOptions{FrontHeadroom: room, RearHeadroom: room/2})
				var retained []*buf.Buffer
				var wants [][]byte
				for _, want := range payloads {
					body, err := r.WaitReadBuffer()
					if want == nil {
						if !errors.Is(err, io.EOF) { t.Fatal(err) }
						r.ReleaseCache() // Preserve next-session read-ahead.
						continue
					}
					if err != nil { t.Fatal(err) }
					if !bytes.Equal(body.Bytes(), want) { t.Fatal("payload mismatch") }
					if body.Start() < room || body.FreeLen() < room/2 { t.Fatal("missing headroom") }
					// Simulate a downstream writer using every promised writable byte.
					clear(body.ExtendHeader(room))
					body.Advance(room)
					clear(body.Extend(room/2))
					body.Truncate(len(want))
					retained = append(retained, body)
					wants = append(wants, want)
				}
				r.releaseStudyStorage()
				var wg sync.WaitGroup
				for i, body := range retained {
					if !bytes.Equal(body.Bytes(), wants[i]) { t.Fatal("later input or close changed retained payload") }
					wg.Add(1)
					go func() { defer wg.Done(); body.Release() }()
				}
				wg.Wait()
				afterBytes, afterBlocks := buf.StudySharedStorage()
				if beforeBytes != afterBytes || beforeBlocks != afterBlocks { t.Fatal("shared storage leaked") }
			})
		}
	}
	}
}

type studyDataAndEOF struct { data []byte }
func (r *studyDataAndEOF) Read(p []byte) (int, error) {
	n := copy(p, r.data)
	r.data = r.data[n:]
	if len(r.data) == 0 { return n, io.EOF }
	return n, nil
}
type studyNoProgress struct{}
func (studyNoProgress) Read([]byte) (int, error) { return 0, nil }

func TestStudySharedReadErrorBoundaries(t *testing.T) {
	wire, _, _, profile := studyWire(t, [][]byte{[]byte("first"), nil, []byte("second")}, true)
	r := newSharedShapedReader(&studyDataAndEOF{data: wire}, studyPSK, profile)
	defer r.releaseStudyStorage()
	for _, want := range [][]byte{[]byte("first"), nil, []byte("second")} {
		body, err := r.ReadRecord()
		if want == nil {
			if !errors.Is(err, io.EOF) { t.Fatal(err) }
			continue
		}
		if err != nil || !bytes.Equal(body.Bytes(), want) { t.Fatalf("data+EOF lost bytes: %v", err) }
		body.Release()
	}
	if _, err := r.ReadRecord(); !errors.Is(err, io.EOF) { t.Fatal(err) }
	stalled := newSharedShapedReader(studyNoProgress{}, studyPSK, profile)
	defer stalled.releaseStudyStorage()
	if _, err := stalled.ReadRecord(); !errors.Is(err, io.ErrNoProgress) { t.Fatal(err) }
}

func TestStudySharedCancelAndQuiescedClose(t *testing.T) {
	beforeBytes, beforeBlocks := buf.StudySharedStorage()
	wire, _, _, profile := studyWire(t, [][]byte{[]byte("retained before cancellation")}, true)
	source, sink := net.Pipe()
	defer sink.Close()
	r := newSharedShapedReader(source, studyPSK, profile)
	go func() { _, _ = sink.Write(wire) }()
	body, err := r.ReadRecord()
	if err != nil { t.Fatal(err) }
	done := make(chan error, 1)
	go func() { _, err := r.ReadRecord(); done <- err }()
	source.Close() // Interrupt a blocked read before freeing reader-owned memory.
	select {
	case err := <-done:
		if err == nil { t.Fatal("closed transport accepted another record") }
	case <-time.After(time.Second):
		t.Fatal("read did not unblock")
	}
	r.releaseStudyStorage()
	if !bytes.Equal(body.Bytes(), []byte("retained before cancellation")) { t.Fatal("close invalidated payload") }
	body.Release()
	afterBytes, afterBlocks := buf.StudySharedStorage()
	if beforeBytes != afterBytes || beforeBlocks != afterBlocks { t.Fatal("close leaked storage") }
}

func TestStudySharedLogicalEOFReleasesDrainedBlock(t *testing.T) {
	beforeBytes, beforeBlocks := buf.StudySharedStorage()
	wire, _, _, profile := studyWire(t, [][]byte{bytes.Repeat([]byte{0x72}, 65535), nil}, true)
	r := newSharedShapedReader(bytes.NewReader(wire), studyPSK, profile)
	defer r.releaseStudyStorage()
	body, err := r.ReadRecord()
	if err != nil { t.Fatal(err) }
	body.Release()
	if _, err := r.ReadRecord(); !errors.Is(err, io.EOF) { t.Fatal(err) }
	afterBytes, afterBlocks := buf.StudySharedStorage()
	if beforeBytes != afterBytes || beforeBlocks != afterBlocks || r.block != nil { t.Fatal("drained logical EOF retained backing storage") }
}

func TestStudyRetainedBackingComparison(t *testing.T) {
	for _, pattern := range []string{"small", "large", "alternating", "medium-isolated"} {
		for _, delay := range []int{0, 1, 32} {
			for _, policy := range []string{"baseline", "shared", "bounded", "detached", "integrated"} {
				t.Run(fmt.Sprintf("%s/retained%d/%s", pattern, delay, policy), func(t *testing.T) {
					var payloads [][]byte
					for i := range 96 {
						size := 64
						if pattern == "large" || (pattern == "alternating" && i%2 == 0) { size = 65535 }
                        if pattern == "medium-isolated" { size = 16384 }
						payloads = append(payloads, bytes.Repeat([]byte{byte(i)}, size))
					}
					wire, ends, _, profile := studyWire(t, payloads, true)
					beforeBytes, beforeBlocks := buf.StudySharedStorage()
					var input io.Reader = bytes.NewReader(wire)
                    if pattern == "medium-isolated" { input = &studyCyclicReader{wire: wire, ends: ends} }
                    r, _ := studyReader(policy, input, profile)
					r.InitializeReadWaiter(N.ReadWaitOptions{FrontHeadroom: *studyFrontHeadroom})
					var held []*buf.Buffer
					var peakRetained, peakDuringRead int64
					measure := func() int64 {
						var bytes int64
						if policy != "baseline" {
							bytes, _ = buf.StudySharedStorage()
							bytes -= beforeBytes
							var owner *buf.Buffer
                            if integrated, ok := r.(*bufferedShapedReader); ok { owner = integrated.block } else { owner = r.(*sharedShapedReader).block }
							if owner != nil && !owner.StudyUsesSharedStorage() { bytes += int64(cap(owner.Bytes())+owner.Start()) }
						}
						for _, body := range held {
							if !body.StudyUsesSharedStorage() { bytes += int64(cap(body.Bytes())+body.Start()) }
						}
						return bytes
					}
					for range payloads {
						body, err := r.ReadRecord()
						if err != nil { t.Fatal(err) }
						held = append(held, body)
						peakDuringRead = max(peakDuringRead, measure())
						if len(held) > delay { held[0].Release(); held = held[1:] }
						peakRetained = max(peakRetained, measure())
					}
					closeStudyReader(r)
					for _, b := range held { b.Release() }
					afterBytes, afterBlocks := buf.StudySharedStorage()
					if beforeBytes != afterBytes || beforeBlocks != afterBlocks { t.Fatal("comparison leaked shared storage") }
					t.Logf("backing-reserved-between-reads=%d peak-backing-at-read-return=%d", peakRetained, peakDuringRead)
				})
			}
		}
	}
}

func TestStudyBoundedSmallRetentionAndLargeCapacity(t *testing.T) {
	beforeBytes, beforeBlocks := buf.StudySharedStorage()
	payloads := [][]byte{bytes.Repeat([]byte{0x51}, 65535)}
	for i := range 32 { payloads = append(payloads, bytes.Repeat([]byte{byte(i)}, 64)) }
	payloads = append(payloads, nil)
	wire, _, _, profile := studyWire(t, payloads, true)
	r := newSharedShapedReader(bytes.NewReader(wire), studyPSK, profile)
	r.enableBounded()
	defer r.releaseStudyStorage()
	large, err := r.ReadRecord()
	if err != nil { t.Fatal(err) }
	if r.peakCapacity > 73728 { t.Fatalf("large record over-reserved: %d", r.peakCapacity) }
	large.Release()
	var held []*buf.Buffer
	for range 32 {
		body, err := r.ReadRecord()
		if err != nil { t.Fatal(err) }
		if body.StudyUsesSharedStorage() { t.Fatal("small payload pinned shared receive storage") }
		held = append(held, body)
	}
	if _, err := r.ReadRecord(); !errors.Is(err, io.EOF) { t.Fatal(err) }
	if r.block != nil { t.Fatal("drained logical EOF kept receive block") }
	for i, body := range held {
		if !bytes.Equal(body.Bytes(), payloads[i+1]) { t.Fatal("retained small payload changed") }
		body.Release()
	}
	afterBytes, afterBlocks := buf.StudySharedStorage()
	if beforeBytes != afterBytes || beforeBlocks != afterBlocks { t.Fatal("storage leaked") }
}

// Report backing memory held by delayed consumers separately from B/op. This
// deliberately measures the cost hidden by immediate-release throughput loops.
func TestStudySharedRetentionAccounting(t *testing.T) {
	for _, pattern := range []string{"small", "large", "alternating"} {
		for _, delay := range []int{0, 1, 32} {
			t.Run(fmt.Sprintf("%s/retained%d", pattern, delay), func(t *testing.T) {
				var payloads [][]byte
				for i := range 96 {
					size := 64
					if pattern == "large" || (pattern == "alternating" && i%2 == 0) { size = 65535 }
					payloads = append(payloads, bytes.Repeat([]byte{byte(i)}, size))
				}
				wire, _, _, profile := studyWire(t, payloads, true)
				beforeBytes, beforeBlocks := buf.StudySharedStorage()
				r := newSharedShapedReader(bytes.NewReader(wire), studyPSK, profile)
				var held []*buf.Buffer
				var peakBytes, peakBlocks, peakPayload int64
				for range payloads {
					body, err := r.ReadRecord()
					if err != nil { t.Fatal(err) }
					held = append(held, body)
					if len(held) > delay { held[0].Release(); held = held[1:] }
					liveBytes, liveBlocks := buf.StudySharedStorage()
					peakBytes = max(peakBytes, liveBytes-beforeBytes)
					peakBlocks = max(peakBlocks, liveBlocks-beforeBlocks)
					var plain int64
					for _, b := range held { plain += int64(b.Len()) }
					peakPayload = max(peakPayload, plain)
				}
				r.releaseStudyStorage()
				for _, b := range held { b.Release() }
				afterBytes, afterBlocks := buf.StudySharedStorage()
				if beforeBytes != afterBytes || beforeBlocks != afterBlocks { t.Fatal("retention leaked") }
				t.Logf("peak-shared-bytes=%d peak-shared-blocks=%d peak-retained-payload=%d copied-bytes=%d peak-block-cap=%d", peakBytes, peakBlocks, peakPayload, r.copiedBytes, r.peakCapacity)
			})
		}
	}
}
