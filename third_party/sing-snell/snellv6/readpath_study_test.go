package snellv6

import (
    "bufio"
    "bytes"
    "crypto/cipher"
    "errors"
    "fmt"
    "flag"
    "io"
    "net"
    "testing"
    "time"

    snell "github.com/sagernet/sing-snell"
    "github.com/sagernet/sing/common/buf"
    N "github.com/sagernet/sing/common/network"
)

// These variants isolate header scratch reuse from ordinary buffered reads.
// No traffic pacing, socket window or delay settings are involved.
var studyBufferSize = flag.Int("study-buffer-size", 4096, "read buffer size for the isolated comparison")
var studyPattern = flag.String("study-pattern", "fixed", "fixed, alternating or bursts record sizes")
var studyDelivery = flag.String("study-delivery", "batch", "batch, channel-gated single, or TCP request/response; memory uses record boundaries for either single mode")
var studyPolicies = []string{"baseline", "scratch", "buffered", "combined", "coalesced", "coalesced_buffered", "adaptive"}
var studySharedFactory func(string, io.Reader, *Profile) (studyRecordReader, func(cipher.AEAD))
var studyPSK = []byte("public snell readpath test fixture, not a server credential")

type studyRecordReader interface {
    ReadRecord() (*buf.Buffer, error)
    InitializeReadWaiter(N.ReadWaitOptions) bool
    WaitReadBuffer() (*buf.Buffer, error)
    Read([]byte) (int, error)
    ReleaseCache()
}

func studyReader(policy string, input io.Reader, profile *Profile) (studyRecordReader, func(cipher.AEAD)) {
    if policy == "shared" || policy == "bounded" { return studySharedFactory(policy, input, profile) }
    if policy == "buffered" || policy == "combined" || policy == "coalesced_buffered" {
        input = bufio.NewReaderSize(input, *studyBufferSize)
    }
    if policy == "baseline" || policy == "buffered" {
        r := newBaselineShapedReader(input, studyPSK, profile)
        return r, func(aead cipher.AEAD) { r.cipher = aead; clear(r.nonce); r.seq = 0 }
    }
    if policy == "adaptive" {
        source := &adaptiveShapedInput{Reader: input, capacity: *studyBufferSize}
        r := newCoalescedShapedReader(bufio.NewReaderSize(source, *studyBufferSize), studyPSK, profile)
        r.controller = source
        return r, func(aead cipher.AEAD) { r.cipher = aead; clear(r.nonce); r.seq = 0 }
    }
    if policy == "coalesced" || policy == "coalesced_buffered" {
        r := newCoalescedShapedReader(input, studyPSK, profile)
        return r, func(aead cipher.AEAD) { r.cipher = aead; clear(r.nonce); r.seq = 0 }
    }
    r := newShapedReader(input, studyPSK, profile)
    return r, func(aead cipher.AEAD) { r.cipher = aead; clear(r.nonce); r.seq = 0 }
}

func closeStudyReader(r studyRecordReader) {
    r.ReleaseCache()
    if owned, ok := r.(interface{ releaseStudyStorage() }); ok { owned.releaseStudyStorage() }
}

func studyWire(t testing.TB, payloads [][]byte, withSalt bool) ([]byte, []int, cipher.AEAD, *Profile) {
    t.Helper()
    salt := bytes.Repeat([]byte{0x35}, snell.SaltLen)
    aead, err := snell.NewAEAD(snell.DeriveKey(studyPSK, salt))
    if err != nil { t.Fatal(err) }
    profile := NewProfile(studyPSK)
    w := newShapedWriter(io.Discard, profile, salt, aead, make([]byte, snell.NonceLen))
    w.saltSent = !withSalt
    var wire []byte
    var ends []int
    for _, p := range payloads {
        record := w.makeSliceRecord(p)
        wire = append(wire, record.Bytes()...)
        ends = append(ends, len(wire))
        record.Release()
    }
    return wire, ends, aead, profile
}

type studyFragmentReader struct { io.Reader; max int }
func (r studyFragmentReader) Read(p []byte) (int, error) { return r.Reader.Read(p[:min(len(p), r.max)]) }

func TestStudyShapedFragmentedAndReusedRecords(t *testing.T) {
    payloads := [][]byte{[]byte("reply and first payload"), bytes.Repeat([]byte{0xaa}, 65535), nil,
        []byte("second logical connection"), bytes.Repeat([]byte{0x55}, 1440), nil}
    wire, _, _, profile := studyWire(t, payloads, true)
    for _, policy := range studyPolicies {
        for _, fragment := range []int{1, 7, 4096, len(wire)} {
            t.Run(fmt.Sprintf("%s/%d", policy, fragment), func(t *testing.T) {
                r, _ := studyReader(policy, studyFragmentReader{bytes.NewReader(wire), fragment}, profile)
                defer closeStudyReader(r)
                r.InitializeReadWaiter(N.ReadWaitOptions{FrontHeadroom: 32, RearHeadroom: 16})
                for _, want := range payloads {
                    record, err := r.WaitReadBuffer()
                    if want == nil {
                        if !errors.Is(err, io.EOF) { t.Fatalf("logical EOF: %v", err) }
                        continue
                    }
                    if err != nil { t.Fatal(err) }
                    if !bytes.Equal(record.Bytes(), want) { t.Fatal("payload changed") }
                    if record.Start() < 32 || record.FreeLen() < 16 { t.Fatal("lost requested headroom") }
                    record.Release()
                }
                if _, err := r.ReadRecord(); !errors.Is(err, io.EOF) { t.Fatalf("transport EOF: %v", err) }
            })
        }
    }
}

func TestStudyShapedPartialReads(t *testing.T) {
    payloads := [][]byte{bytes.Repeat([]byte{0xa7}, 1440), bytes.Repeat([]byte{0x3e}, 16384)}
    wire, _, _, profile := studyWire(t, append(payloads, nil), true)
    want := bytes.Join(payloads, nil)
    for _, policy := range studyPolicies {
        t.Run(policy, func(t *testing.T) {
            r, _ := studyReader(policy, bytes.NewReader(wire), profile)
            defer closeStudyReader(r)
            var got bytes.Buffer
            scratch := make([]byte, 17)
            for {
                n, err := r.Read(scratch)
                got.Write(scratch[:n])
                if errors.Is(err, io.EOF) { break }
                if err != nil { t.Fatal(err) }
            }
            if !bytes.Equal(got.Bytes(), want) { t.Fatal("partial read changed bytes") }
        })
    }
}

func TestStudyShapedTruncationAndAuthentication(t *testing.T) {
    wire, _, _, profile := studyWire(t, [][]byte{bytes.Repeat([]byte{0x74}, 64)}, true)
    for _, policy := range studyPolicies {
        t.Run(policy, func(t *testing.T) {
            for cut := range len(wire) {
                r, _ := studyReader(policy, bytes.NewReader(wire[:cut]), profile)
                body, err := r.ReadRecord()
                if body != nil { body.Release() }
                closeStudyReader(r)
                if err == nil { t.Fatalf("accepted truncation at %d", cut) }
            }
            // The prefix is authenticated as header AAD; the header and payload
            // have independent tags. Each corruption must reject the record.
            for _, offset := range []int{profile.saltBlockLen, profile.saltBlockLen + profile.recordPrefixLen(0), len(wire)-1} {
                corrupt := bytes.Clone(wire)
                corrupt[offset] ^= 0x80
                r, _ := studyReader(policy, bytes.NewReader(corrupt), profile)
                body, err := r.ReadRecord()
                if body != nil { body.Release() }
                closeStudyReader(r)
                if err == nil { t.Fatalf("accepted corruption at %d", offset) }
            }
        })
    }
}

func TestStudyShapedDoesNotWaitForNextRecord(t *testing.T) {
    wire, _, _, profile := studyWire(t, [][]byte{[]byte("short response")}, true)
    for _, policy := range studyPolicies {
        t.Run(policy, func(t *testing.T) {
            source, sink := net.Pipe()
            defer source.Close()
            defer sink.Close()
            go func() { _, _ = sink.Write(wire) }() // Leave open, with no next frame.
            r, _ := studyReader(policy, source, profile)
            done := make(chan error, 1)
            go func() {
                body, err := r.ReadRecord()
                if body != nil { body.Release() }
                closeStudyReader(r)
                done <- err
            }()
            select {
            case err := <-done:
                if err != nil { t.Fatal(err) }
            case <-time.After(time.Second):
                t.Fatal("complete response waited for more network data")
            }
        })
    }
}

type studyCyclicReader struct { wire []byte; offset int; calls uint64; ends []int; frame int }
func (r *studyCyclicReader) Read(p []byte) (int, error) {
    r.calls++
    if r.offset == len(r.wire) { r.offset = 0; r.frame = 0 }
    end := len(r.wire)
    if len(r.ends) > 0 {
        for r.offset == r.ends[r.frame] { r.frame++ }
        end = r.ends[r.frame]
    }
    n := copy(p, r.wire[r.offset:end])
    r.offset += n
    return n, nil
}
type studyCountingReader struct { io.Reader; calls uint64 }
func (r *studyCountingReader) Read(p []byte) (int, error) { r.calls++; return r.Reader.Read(p) }

func BenchmarkStudyShapedRead(b *testing.B) {
    for _, size := range []int{64, 1440, 4096, 8192, 16384, 65535} {
        for _, transport := range []string{"memory", "tcp"} {
            for _, policy := range studyPolicies {
                b.Run(fmt.Sprintf("%s/%d/%s", transport, size, policy), func(b *testing.B) {
                    payloads := make([][]byte, 32)
                    totalPlain := 0
                    for i := range payloads {
                        recordSize := size
                        if (*studyPattern == "alternating" && i%2 == 1) || (*studyPattern == "bursts" && i >= 16) { recordSize = 64 }
                        payloads[i] = bytes.Repeat([]byte{byte(i)}, recordSize)
                        totalPlain += recordSize
                    }
                    wire, ends, aead, profile := studyWire(b, payloads, false)
                    cyclic := &studyCyclicReader{wire: wire}
                    if *studyDelivery != "batch" { cyclic.ends = ends }
                    var input io.Reader = cyclic
                    var receiver, sender *net.TCPConn
                    var counted *studyCountingReader
                    done := make(chan error, 1)
                    acknowledged := make(chan struct{})
                    if transport == "tcp" {
                        listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127,0,0,1)})
                        if err != nil { b.Fatal(err) }
                        receiver, err = net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
                        if err != nil { listener.Close(); b.Fatal(err) }
                        sender, err = listener.AcceptTCP()
                        listener.Close()
                        if err != nil { receiver.Close(); b.Fatal(err) }
                        defer receiver.Close()
                        defer sender.Close()
                        receiver.SetDeadline(time.Now().Add(30*time.Second))
                        sender.SetDeadline(time.Now().Add(30*time.Second))
                        counted = &studyCountingReader{Reader: receiver}
                        input = counted
                    }
                    reader, reset := studyReader(policy, input, profile)
                    defer closeStudyReader(reader)
                    b.SetBytes(int64(totalPlain/len(payloads)))
                    b.ReportAllocs()
                    b.ResetTimer()
                    cpuStart := studyProcessCPU()
                    if transport == "tcp" {
                        go func() {
                            if *studyDelivery == "single" || *studyDelivery == "request" {
                                var request [1]byte
                                for i := 0; i < b.N; i++ {
                                    if *studyDelivery == "request" {
                                        if _, err := io.ReadFull(sender, request[:]); err != nil { done <- err; return }
                                    }
                                    index := i % 32
                                    start := 0
                                    if index > 0 { start = ends[index-1] }
                                    if _, err := sender.Write(wire[start:ends[index]]); err != nil { done <- err; return }
                                    if *studyDelivery == "single" { <-acknowledged }
                                }
                                done <- nil
                                return
                            }
                            for left := b.N; left > 0; {
                                count := min(left, 32)
                                if _, err := sender.Write(wire[:ends[count-1]]); err != nil { done <- err; return }
                                left -= count
                            }
                            done <- nil
                        }()
                    }
                    var request [1]byte
                    for i := 0; i < b.N; i++ {
                        if i % 32 == 0 { reset(aead) }
                        if transport == "tcp" && *studyDelivery == "request" {
                            if _, err := receiver.Write(request[:]); err != nil { b.Fatal(err) }
                        }
                        body, err := reader.ReadRecord()
                        if err != nil { b.Fatal(err) }
                        if body.Len() != len(payloads[i%32]) { b.Fatal("wrong record size") }
                        body.Release()
                        if transport == "tcp" && *studyDelivery == "single" { acknowledged <- struct{}{} }
                    }
                    cpuElapsed := studyProcessCPU() - cpuStart
                    b.StopTimer()
                    calls := cyclic.calls
                    if transport == "tcp" {
                        if err := <-done; err != nil { b.Fatal(err) }
                        calls = counted.calls
                    }
                    b.ReportMetric(float64(calls)/float64(b.N), "reads/record")
                    if cpuElapsed > 0 { b.ReportMetric(float64(cpuElapsed)/float64(b.N), "process-cpu-ns/record") }
                    if tracked, ok := reader.(interface{ studyMetrics() (uint64, int) }); ok {
                        copied, capacity := tracked.studyMetrics()
                        b.ReportMetric(float64(copied)/float64(b.N), "copied-B/record")
                        b.ReportMetric(float64(capacity), "block-cap-B")
                    }
                })
            }
        }
    }
}
