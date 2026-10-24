package snellv6

import (
	"bytes"
	"io"
	"testing"

	snell "github.com/sagernet/sing-snell"
)

func helloTestRecords(t *testing.T, key []byte, sizes []int) ([]byte, []int) {
	t.Helper()
	salt := bytes.Repeat([]byte{0xb1}, saltLen)
	aead, err := snell.NewAEAD(snell.DeriveKey(key, salt))
	if err != nil {
		t.Fatal(err)
	}
	w := newShapedWriter(io.Discard, NewProfile(key), salt, aead, make([]byte, snell.NonceLen))
	var wire []byte
	var ends []int
	for i, n := range sizes {
		r := w.makeSliceRecord(bytes.Repeat([]byte{byte(i + 11)}, n))
		wire = append(wire, r.Bytes()...)
		r.Release()
		ends = append(ends, len(wire))
	}
	return wire, ends
}

func TestHelloRecordsConsecutiveIncludingEmptyAndPartial(t *testing.T) {
	key := []byte("public multi record nonce and bounds key")
	c := newHelloRecordCodec(key)
	wire, ends := helloTestRecords(t, key, []int{1, 0, 2, 128, 0, 512})
	packed, take, mode, err := c.Pack(wire, 1307)
	if err != nil || mode != 2 || take != len(wire) || packed[1] != 6 {
		t.Fatalf("whole batch: mode%d taken%d/%d err%v", mode, take, len(wire), err)
	}
	before := append([]byte(nil), packed...)
	restored, err := c.Unpack(packed)
	if err != nil || !bytes.Equal(restored, wire) || !bytes.Equal(packed, before) {
		t.Fatal("empty record nonce or byte identity failed", err)
	}
	for end := 0; end < len(packed); end++ {
		if _, err := c.Unpack(packed[:end]); err == nil {
			t.Fatalf("accepted truncated multi record at%d", end)
		}
	}
	for _, count := range []byte{0, 1, helloMaxCompactRecords + 1, 255} {
		bad := append([]byte(nil), packed...)
		bad[1] = count
		if _, err := c.Unpack(bad); err == nil {
			t.Fatal("invalid count accepted", count)
		}
	}
	secondHeader := 2 + saltLen + snell.HeaderCipherLen + 1 + snell.AEADTagLen
	bad := append([]byte(nil), packed...)
	bad[secondHeader+snell.HeaderCipherLen-1] ^= 1
	if _, err := c.Unpack(bad); err == nil {
		t.Fatal("corrupt second header accepted")
	}
	// A later record may remain partially raw. Every possible input truncation
	// must either restore exactly the chosen prefix or stop at the last record.
	for end := ends[0]; end < len(wire); end++ {
		p, n, _, err := c.Pack(wire[:end], 411)
		if err != nil {
			t.Fatal(end, err)
		}
		r, err := c.Unpack(p)
		if err != nil || !bytes.Equal(r, wire[:n]) {
			t.Fatal("partial original record changed", end, err)
		}
	}
	// Padding in the second (empty) record is not mixed with a ciphertext.
	padAt := ends[0] + c.profile.recordPrefixLen(1) + snell.HeaderCipherLen
	if padAt >= ends[1] {
		t.Fatal("test requires second record padding")
	}
	badWire := append([]byte(nil), wire...)
	badWire[padAt] ^= 1
	if _, _, _, err := c.Pack(badWire, 1307); err == nil {
		t.Fatal("second record nonreproducible padding discarded")
	}
}

func TestHelloRecordsBoundCountAndAuthenticatedExpansion(t *testing.T) {
	key := []byte("public multi record expansion bound key")
	c := newHelloRecordCodec(key)
	wire, _ := helloTestRecords(t, key, make([]int, helloMaxCompactRecords*2))
	p, n, mode, err := c.Pack(wire, 4096)
	if err != nil || mode != 2 || p[1] != helloMaxCompactRecords {
		t.Fatal("record count not bounded", mode, err)
	}
	r, err := c.Unpack(p)
	if err != nil || !bytes.Equal(r, wire[:n]) {
		t.Fatal("count bound changed suffix", err)
	}
	// An authenticated but pathological set of lengths must not permit an
	// attacker possessing the key to force unbounded per-connection expansion.
	saltPositions, err := c.prefix.Pack(wire[:c.prefix.PrefixSize()])
	if err != nil {
		t.Fatal(err)
	}
	state, err := c.recordState(wire[:c.prefix.PrefixSize()])
	if err != nil {
		t.Fatal(err)
	}
	huge := append([]byte{2, 5}, saltPositions...)
	for seq := 0; seq < 5; seq++ {
		prefix := make([]byte, c.profile.recordPrefixLen(uint32(seq)))
		c.profile.fillPadding(uint32(seq), prefix)
		header := make([]byte, snell.HeaderPlainLen)
		putHeader(header, 65535, 0)
		huge = state.aead.Seal(huge, state.nonce, header, prefix)
		snell.IncreaseNonce(state.nonce)
	}
	if _, err := c.Unpack(huge); err == nil {
		t.Fatal("unbounded authenticated expansion accepted")
	}
}
