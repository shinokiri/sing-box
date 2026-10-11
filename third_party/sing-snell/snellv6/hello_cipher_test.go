package snellv6

import (
	"bytes"
	"crypto/cipher"
	"fmt"
	"testing"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing/common/buf"
)

type helloCountingCipher struct {
	cipher.AEAD
	opens int
}

func (c *helloCountingCipher) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	c.opens++
	return c.AEAD.Open(dst, nonce, ciphertext, additionalData)
}

func TestHelloExistingCipherPreservesCompactEncoding(t *testing.T) {
	for k := 0; k < 12; k++ {
		key := []byte(fmt.Sprintf("public first-cipher fixture %d", k))
		codec := newHelloRecordCodec(key)
		salt := bytes.Repeat([]byte{0xb1}, saltLen)
		aead, err := snell.NewAEAD(snell.DeriveKey(key, salt))
		if err != nil {
			t.Fatal(err)
		}
		counted := &helloCountingCipher{AEAD: aead}
		hint := &helloCipherHint{aead: counted}
		copy(hint.salt[:], salt)
		for _, sizes := range [][]int{{0}, {1}, {512}, {16, 512}, {16, 2048}, {1, 0, 2, 128, 0, 512}, {40000}} {
			wire := helloCostWire(t, key, sizes)
			for _, budget := range []int{171, 411, 1095, 1115, 1307, 4096} {
				want, take, mode, err := codec.Pack(wire, budget)
				if err != nil {
					t.Fatal(err)
				}
				got, n, m, err := codec.pack(wire, budget, hint, false)
				if err != nil || n != take || m != mode || !bytes.Equal(got, want) {
					t.Fatal("existing cipher changed bytes or mode", k, sizes, budget, err)
				}
				if counted.opens == 0 {
					t.Fatal("prepared cipher was not used")
				}
			}
		}
		wire := helloCostWire(t, key, []int{512})
		badHint := *hint
		badHint.salt[0] ^= 1
		if _, _, _, err = codec.pack(wire, 1115, &badHint, false); err == nil {
			t.Fatal("cipher belonging to a different salt was accepted")
		}
		badWire := bytes.Clone(wire)
		badWire[codec.prefix.PrefixSize()+snell.HeaderCipherLen-1] ^= 1
		if _, _, _, err = codec.pack(badWire, 1115, hint, false); err == nil {
			t.Fatal("corrupted header was accepted with prepared cipher")
		}
	}
}

func TestHelloCompletePrefixPreservesAllEarlyBytes(t *testing.T) {
	full, compact := 0, 0
	for k := 0; k < 32; k++ {
		key := []byte(fmt.Sprintf("public prefix selection fixture %d", k))
		codec := newHelloRecordCodec(key)
		for _, sizes := range [][]int{{0}, {1}, {3}, {16}, {512}, {16, 512}, {16, 2048}, {1, 0, 2, 128, 0, 512}, {40000}} {
			wire := helloCostWire(t, key, sizes)
			for _, budget := range []int{171, 411, 1095, 1115, 1307, 4096} {
				before, take, mode, err := codec.Pack(wire, budget)
				if err != nil {
					t.Fatal(err)
				}
				packed, n, m, err := codec.pack(wire, budget, nil, true)
				if err != nil || len(packed) > budget {
					t.Fatal(err)
				}
				restored, err := codec.Unpack(packed)
				if err != nil || !bytes.Equal(restored, wire[:n]) {
					t.Fatal("wire identity", err)
				}
				if len(wire) <= budget-1+codec.prefix.SavedBytes() {
					full++
					if m != 0 || n != len(wire) {
						t.Fatal("incomplete early prefix")
					}
				} else {
					compact++
					if n != take || m != mode || !bytes.Equal(packed, before) {
						t.Fatal("compaction changed")
					}
				}
			}
		}
	}
	if full == 0 || compact == 0 {
		t.Fatal("missing full or compact cases")
	}
}

type helloCipherWatch struct {
	*helloConn
	sawCipher bool
}

func (c *helloCipherWatch) Upstream() any { return c.helloConn }
func (c *helloCipherWatch) Write(p []byte) (int, error) {
	c.sawCipher = c.firstCipher != nil
	return c.helloConn.Write(p)
}

func TestHelloCipherHintHandshakeLifetime(t *testing.T) {
	for _, buffered := range []bool{false, true} {
		transport, _ := NewHelloTransport(helloTestPSK)
		raw := new(helloMemoryConn)
		conn := transport.Wrap(raw, "test").(*helloConn)
		watch := &helloCipherWatch{helloConn: conn}
		payload := bytes.Repeat([]byte{0x79}, 8192)
		var err error
		if buffered {
			profile := NewProfile(helloTestPSK)
			b := buf.NewSize(profile.saltBlockLen + profile.recordPrefixMax + snell.HeaderCipherLen + profile.padMaxHeadroom + len(payload) + snell.AEADTagLen)
			b.Resize(profile.saltBlockLen+profile.recordPrefixMax+snell.HeaderCipherLen+profile.padMaxHeadroom, 0)
			_, _ = b.Write(payload)
			_, err = writeFirstRecordBuffer(watch, ModeDefault, helloTestPSK, profile, b)
		} else {
			_, err = writeFirstRecord(watch, ModeDefault, helloTestPSK, NewProfile(helloTestPSK), payload)
		}
		if err != nil || !watch.sawCipher || conn.firstCipher != nil {
			t.Fatal("hint lifecycle", buffered, err, watch.sawCipher)
		}
		if _, err = transport.DecodeHello(bytes.NewReader(raw.Bytes())); err != nil {
			t.Fatal(err)
		}
	}
	transport, _ := NewHelloTransport(helloTestPSK)
	conn := transport.Wrap(new(helloMemoryConn), "test").(*helloConn)
	salt := bytes.Repeat([]byte{1}, saltLen)
	aead, _ := snell.NewAEAD(snell.DeriveKey(helloTestPSK, salt))
	helloFirstRecordCipher(conn, []byte("different public key"), salt, aead)
	if conn.firstCipher != nil {
		t.Fatal("a different transport PSK supplied a hint")
	}
}

func BenchmarkHelloPreparedCipher(b *testing.B) {
	key := []byte("public prepared-cipher benchmark key")
	codec := newHelloRecordCodec(key)
	salt := bytes.Repeat([]byte{0xb1}, saltLen)
	aead, err := snell.NewAEAD(snell.DeriveKey(key, salt))
	if err != nil {
		b.Fatal(err)
	}
	hint := &helloCipherHint{aead: aead}
	copy(hint.salt[:], salt)
	for _, tc := range []struct {
		name  string
		sizes []int
	}{{"single512", []int{512}}, {"large2048", []int{16, 2048}}, {"multi", []int{1, 0, 2, 128, 0, 512}}} {
		wire := helloCostWire(b, key, tc.sizes)
		for _, prepared := range []bool{false, true} {
			b.Run(fmt.Sprintf("%s/prepared%v", tc.name, prepared), func(b *testing.B) {
				b.ReportAllocs()
				var use *helloCipherHint
				if prepared {
					use = hint
				}
				for b.Loop() {
					var err error
					helloBenchmarkSink, _, _, err = codec.pack(wire, 1115, use, false)
					if err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
