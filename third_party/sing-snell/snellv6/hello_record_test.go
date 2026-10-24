package snellv6

import (
	"bytes"
	"fmt"
	"testing"

	snell "github.com/sagernet/sing-snell"
)

func TestHelloRecordCodecActualWireRoundTrip(t *testing.T) {
	whole, prefix, multi := 0, 0, 0
	for keyID := 0; keyID < 12; keyID++ {
		key := []byte(fmt.Sprintf("public full-record diagnostic test key %d", keyID))
		codec := newHelloRecordCodec(key)
		for _, size := range []int{0, 1, 16, 128, 512, 1024, 2048, 40000} {
			data := make([]byte, size)
			for i := range data {
				data[i] = byte(i*137 + size)
			}
			var wire bytes.Buffer
			if _, err := writeFirstRecord(&wire, ModeDefault, key, NewProfile(key), data); err != nil {
				t.Fatal(err)
			}
			before := append([]byte(nil), wire.Bytes()...)
			for _, budget := range []int{171, 517, 1207, 1307} {
				packed, consumed, mode, err := codec.Pack(wire.Bytes(), budget)
				if err != nil {
					t.Fatal(keyID, size, budget, err)
				}
				if len(packed) > budget || consumed > wire.Len() {
					t.Fatal("budget or source exceeded")
				}
				restored, err := codec.Unpack(packed)
				if err != nil || !bytes.Equal(restored, before[:consumed]) {
					t.Fatalf("wire identity failed key%d size%d budget%d mode%d err%v", keyID, size, budget, mode, err)
				}
				if !bytes.Equal(append(restored, before[consumed:]...), before) {
					t.Fatal("original suffix altered")
				}
				if !bytes.Equal(wire.Bytes(), before) {
					t.Fatal("source ciphertext was mutated")
				}
				if mode == 1 || mode == 2 {
					whole++
					headerStart := 1 + saltLen
					if mode == 2 {
						multi++
						headerStart++
					}
					bad := append([]byte(nil), packed...)
					bad[headerStart+snell.HeaderCipherLen-1] ^= 1
					if _, err := codec.Unpack(bad); err == nil {
						t.Fatal("corrupt authenticated header accepted")
					}
					if _, err := newHelloRecordCodec([]byte("different public key")).Unpack(packed); err == nil {
						t.Fatal("wrong key accepted")
					}
				} else {
					prefix++
				}
			}
		}
	}
	if whole == 0 || prefix == 0 || multi == 0 {
		t.Fatal("complete-record, multiple-record and prefix paths must be exercised")
	}
	t.Logf("whole-record=%d prefix=%d multi=%d", whole, prefix, multi)
}

func TestHelloRecordCodecRejectsShortAndUnknown(t *testing.T) {
	c := newHelloRecordCodec([]byte("public codec bounds test key"))
	for _, p := range [][]byte{nil, {9}, {1}, {1, 0}, {0}, {0, 1, 2}} {
		if _, err := c.Unpack(p); err == nil {
			t.Fatalf("accepted incomplete or unknown packed value of%d bytes", len(p))
		}
	}
}

func TestHelloRecordCodecDoesNotDiscardUnexpectedPadding(t *testing.T) {
	key := []byte("public nonreproducible-padding diagnostic key")
	c := newHelloRecordCodec(key)
	var wire bytes.Buffer
	if _, err := writeFirstRecord(&wire, ModeDefault, key, NewProfile(key), bytes.Repeat([]byte{0xa5}, 128)); err != nil {
		t.Fatal(err)
	}
	headLen := c.prefix.PrefixSize() + snell.HeaderCipherLen
	padSize, dataSize, err := c.header(wire.Bytes()[:headLen])
	if err != nil {
		t.Fatal(err)
	}
	if padSize == 0 {
		t.Fatal("test needs a padded profile")
	}
	bad := append([]byte(nil), wire.Bytes()...)
	body := bad[headLen : headLen+padSize+dataSize+snell.AEADTagLen]
	c.profile.mixPaddingPayload(0, body[:padSize], body[padSize:])
	body[0] ^= 1
	c.profile.mixPaddingPayload(0, body[:padSize], body[padSize:])
	if _, _, _, err := c.Pack(bad, 1307); err == nil {
		t.Fatal("unexpected padding byte was silently discarded")
	}
}

func TestHelloPrefixChecksEveryOmittedByte(t *testing.T) {
	for k := 0; k < 12; k++ {
		codec := newHelloPrefixCodec([]byte(fmt.Sprintf("public omitted-prefix byte fixture %d", k)))
		original := append([]byte(nil), codec.template...)
		var saltPosition [256]bool
		for i, at := range codec.positions {
			original[at] = byte(i + 17)
			saltPosition[at] = true
		}
		for at := range original {
			original[at] ^= 1
			packed, err := codec.Pack(original)
			if at < len(saltPosition) && saltPosition[at] {
				if err != nil {
					t.Fatal("variable salt byte rejected", k, at, err)
				}
				restored, err := codec.Unpack(packed)
				if err != nil || !bytes.Equal(restored, original) {
					t.Fatal("variable salt byte lost", k, at, err)
				}
			} else if err == nil {
				t.Fatal("modified omitted byte silently discarded", k, at)
			}
			original[at] ^= 1
		}
	}
}
