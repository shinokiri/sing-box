package snellv6

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
)

// This experiment does not change production code. It compares the original
// WriteBuffer with the same framing/encryption and a borrowed vector write in
// place of the final concatenate-and-write operation. Pinning overhead is part
// of the candidate, so the result does not assume a free ownership transfer.
func studyWriteBufferVector(w *shapedWriter, buffer *buf.Buffer, vector N.VectorisedWriter) error {
	defer buffer.Release()
	dataLen := buffer.Len()
	if dataLen == 0 {
		return nil
	}
	w.access.Lock()
	defer w.access.Unlock()
	now := time.Now()
	payloadLimit := w.payloadLimitFor(now)
	if dataLen <= payloadLimit {
		w.makeBufferRecord(buffer)
		_, err := w.upstream.Write(buffer.Bytes())
		return err
	}
	var records []*buf.Buffer
	defer func() { buf.ReleaseMulti(records) }()
	for data := buffer.Bytes(); len(data) > 0; {
		recordLen := min(len(data), payloadLimit)
		records = append(records, w.makeSliceRecord(data[:recordLen]))
		data = data[recordLen:]
		if len(data) > 0 {
			payloadLimit = w.payloadLimitFor(now)
		}
	}
	for _, record := range records {
		record.IncRef()
	}
	err := vector.WriteVectorised(records)
	for _, record := range records {
		record.DecRef()
	}
	return err
}

func studyWriter(t testing.TB, upstream io.Writer, profileID int) (*shapedWriter, []byte) {
	t.Helper()
	psk := []byte(fmt.Sprintf("public writepath fixture %d", profileID))
	salt := bytes.Repeat([]byte{0x53}, snell.SaltLen)
	aead, err := snell.NewAEAD(snell.DeriveKey(psk, salt))
	if err != nil {
		t.Fatal(err)
	}
	return newShapedWriter(upstream, NewProfile(psk), salt, aead, make([]byte, snell.NonceLen)), psk
}

func studyPayload(w *shapedWriter, data []byte) *buf.Buffer {
	buffer := buf.NewSize(w.FrontHeadroom() + len(data) + w.RearHeadroom())
	buffer.Resize(w.FrontHeadroom(), 0)
	buffer.Write(data)
	return buffer
}

type studyCaptureVector struct {
	bytes.Buffer
	vectorCalls int
	records     int
}

func (w *studyCaptureVector) WriteVectorised(buffers []*buf.Buffer) error {
	w.vectorCalls++
	w.records += len(buffers)
	defer buf.ReleaseMulti(buffers)
	for _, buffer := range buffers {
		w.Buffer.Write(buffer.Bytes())
	}
	return nil
}

func TestWritePathStudyEquivalent(t *testing.T) {
	for profileID := range 8 {
		t.Run(fmt.Sprint(profileID), func(t *testing.T) {
			var original bytes.Buffer
			var candidate studyCaptureVector
			baseline, psk := studyWriter(t, &original, profileID)
			vector, _ := studyWriter(t, &candidate, profileID)
			var wants [][]byte
			for i := range 48 {
				size := []int{64, 1440, 16384, 32768, 65535, 1}[i%6]
				data := bytes.Repeat([]byte{byte(i)}, size)
				wants = append(wants, data)
				if err := baseline.WriteBuffer(studyPayload(baseline, data)); err != nil {
					t.Fatal(err)
				}
				if err := studyWriteBufferVector(vector, studyPayload(vector, data), &candidate); err != nil {
					t.Fatal(err)
				}
			}
			if !bytes.Equal(original.Bytes(), candidate.Bytes()) {
				t.Fatal("candidate changed encrypted record bytes")
			}
			if candidate.vectorCalls == 0 {
				t.Fatal("fixture did not exercise multiple-record writes")
			}
			// Decode the full stream to include record boundaries and padding.
			reader := newBufferedShapedReader(bytes.NewReader(candidate.Bytes()), psk, NewProfile(psk))
			defer reader.releaseReceive()
			reader.InitializeReadWaiter(N.ReadWaitOptions{})
			var got []byte
			for {
				buffer, err := reader.WaitReadBuffer()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				got = append(got, buffer.Bytes()...)
				buffer.Release()
			}
			if !bytes.Equal(got, bytes.Join(wants, nil)) {
				t.Fatal("decoded payload mismatch")
			}
			t.Logf("vector_calls=%d records=%d ciphertext_bytes=%d", candidate.vectorCalls, candidate.records, candidate.Len())
		})
	}
}

func BenchmarkWritePathStudy(b *testing.B) {
	variants := []bool{false, true}
	if os.Getenv("STUDY_REVERSE") == "true" {
		variants = []bool{true, false}
	}
	for _, size := range []int{64, 1440, 16384, 65535} {
		for _, cold := range []bool{false, true} {
			for _, vector := range variants {
				b.Run(fmt.Sprintf("bytes%d/cold%t/vector%t", size, cold, vector), func(b *testing.B) {
					listener, err := net.Listen("tcp4", "127.0.0.1:0")
					if err != nil {
						b.Fatal(err)
					}
					done := make(chan error, 1)
					go func() {
						peer, err := listener.Accept()
						if err == nil {
							_, err = io.Copy(io.Discard, peer)
							peer.Close()
						}
						done <- err
					}()
					conn, err := net.Dial("tcp4", listener.Addr().String())
					if err != nil {
						listener.Close()
						b.Fatal(err)
					}
					b.Cleanup(func() {
						conn.Close()
						listener.Close()
						if err := <-done; err != nil {
							b.Error(err)
						}
					})
					writer, _ := studyWriter(b, conn, 0)
					vectorWriter := bufio.NewVectorisedWriter(conn)
					data := bytes.Repeat([]byte{0x6d}, size)
					if !cold {
						for range 64 {
							if err := writer.WriteBuffer(studyPayload(writer, data)); err != nil {
								b.Fatal(err)
							}
						}
					}
					b.ReportAllocs()
					b.SetBytes(int64(size))
					b.ResetTimer()
					for range b.N {
						if cold {
							writer.seq, writer.chunkSize, writer.lastWriteUnix = 0, 0, 0
							writer.saltSent = false
							clear(writer.nonce)
						}
						buffer := studyPayload(writer, data)
						var err error
						if vector {
							err = studyWriteBufferVector(writer, buffer, vectorWriter)
						} else {
							err = writer.WriteBuffer(buffer)
						}
						if err != nil {
							b.Fatal(err)
						}
					}
					b.StopTimer()
				})
			}
		}
	}
}
