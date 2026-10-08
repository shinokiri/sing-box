package snellv6

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"
)

func shapedReaderFixture(t *testing.T, psk []byte, payloads [][]byte) ([]byte, *Profile) {
	t.Helper()
	salt := bytes.Repeat([]byte{0x35}, snell.SaltLen)
	aead, err := snell.NewAEAD(snell.DeriveKey(psk, salt))
	if err != nil {
		t.Fatal(err)
	}
	profile := NewProfile(psk)
	writer := newShapedWriter(io.Discard, profile, salt, aead, make([]byte, snell.NonceLen))
	var wire []byte
	for _, payload := range payloads {
		record := writer.makeSliceRecord(payload)
		wire = append(wire, record.Bytes()...)
		record.Release()
	}
	return wire, profile
}

type fragmentedShapedInput struct {
	io.Reader
	maximum int
}

func (r fragmentedShapedInput) Read(p []byte) (int, error) {
	return r.Reader.Read(p[:min(len(p), r.maximum)])
}

func TestShapedReaderFragmentationAndLogicalEOF(t *testing.T) {
	payloads := [][]byte{
		[]byte("reply and first payload"), bytes.Repeat([]byte{0xaa}, 65535), nil,
		[]byte("second logical connection"), bytes.Repeat([]byte{0x55}, 1440), nil,
	}
	for profileNumber := range 8 {
		psk := []byte(fmt.Sprintf("public shaped reader fixture %d", profileNumber))
		wire, profile := shapedReaderFixture(t, psk, payloads)
		for _, fragment := range []int{1, 7, 1024, len(wire)} {
			t.Run(fmt.Sprintf("profile%d/fragment%d", profileNumber, fragment), func(t *testing.T) {
				input := fragmentedShapedInput{Reader: bytes.NewReader(wire), maximum: fragment}
				reader := newShapedReader(input, psk, profile)
				reader.InitializeReadWaiter(N.ReadWaitOptions{FrontHeadroom: 32, RearHeadroom: 16})
				var retained []*buf.Buffer
				defer func() {
					for _, record := range retained {
						record.Release()
					}
				}()
				for _, want := range payloads {
					record, err := reader.WaitReadBuffer()
					if want == nil {
						if !errors.Is(err, io.EOF) {
							t.Fatalf("logical EOF: %v", err)
						}
						continue
					}
					if err != nil {
						t.Fatal(err)
					}
					retained = append(retained, record)
					if !bytes.Equal(record.Bytes(), want) {
						t.Fatal("payload changed")
					}
					if record.Start() < 32 || record.FreeLen() < 16 {
						t.Fatal("lost requested headroom")
					}
				}
				if _, err := reader.ReadRecord(); !errors.Is(err, io.EOF) {
					t.Fatalf("transport EOF: %v", err)
				}
				index := 0
				for _, want := range payloads {
					if want != nil {
						if !bytes.Equal(retained[index].Bytes(), want) {
							t.Fatal("a later read modified an earlier returned payload")
						}
						index++
					}
				}
			})
		}
	}
}

func TestShapedReaderPartialReads(t *testing.T) {
	psk := []byte("public shaped partial-read fixture")
	payloads := [][]byte{bytes.Repeat([]byte{0xa7}, 1440), bytes.Repeat([]byte{0x3e}, 16384)}
	wire, profile := shapedReaderFixture(t, psk, append(payloads, nil))
	input := bytes.NewReader(wire)
	reader := newShapedReader(input, psk, profile)
	defer reader.ReleaseCache()
	if reader.Upstream() != input {
		t.Fatal("changed the exposed upstream reader")
	}
	var got bytes.Buffer
	scratch := make([]byte, 17)
	for {
		n, err := reader.Read(scratch)
		got.Write(scratch[:n])
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(got.Bytes(), bytes.Join(payloads, nil)) {
		t.Fatal("partial read changed bytes")
	}
}

func TestShapedReaderTruncationAndAuthentication(t *testing.T) {
	psk := []byte("public shaped authentication fixture")
	wire, profile := shapedReaderFixture(t, psk, [][]byte{bytes.Repeat([]byte{0x74}, 64)})
	for cut := range len(wire) {
		reader := newShapedReader(bytes.NewReader(wire[:cut]), psk, profile)
		body, err := reader.ReadRecord()
		if body != nil {
			body.Release()
		}
		if err == nil {
			t.Fatalf("accepted truncation at %d", cut)
		}
	}
	// The prefix is header AAD; the header and payload have separate tags.
	for _, offset := range []int{profile.saltBlockLen, profile.saltBlockLen + profile.recordPrefixLen(0), len(wire) - 1} {
		corrupt := bytes.Clone(wire)
		corrupt[offset] ^= 0x80
		reader := newShapedReader(bytes.NewReader(corrupt), psk, profile)
		body, err := reader.ReadRecord()
		if body != nil {
			body.Release()
		}
		if err == nil {
			t.Fatalf("accepted corruption at %d", offset)
		}
	}
}

func TestShapedReaderReturnsCompleteMessageImmediately(t *testing.T) {
	psk := []byte("public shaped short-message fixture")
	wire, profile := shapedReaderFixture(t, psk, [][]byte{[]byte("short response")})
	source, sink := net.Pipe()
	defer source.Close()
	defer sink.Close()
	go func() {
		_, _ = sink.Write(wire)
	}() // Keep the connection open, with no following frame or EOF.
	reader := newShapedReader(source, psk, profile)
	done := make(chan error, 1)
	go func() {
		body, err := reader.ReadRecord()
		if body != nil {
			body.Release()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("a complete response waited for more network data")
	}
}
