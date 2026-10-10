package snellv6

// helloRecordCodec omits reproducible padding from initial shaped records.
// It preserves the salt positions, authenticated header ciphertext, payload
// ciphertext and tags. The receiver restores the exact original encrypted wire
// bytes before passing them to the existing Snell server.
import (
	"bytes"
	"encoding/binary"
	"fmt"

	snell "github.com/sagernet/sing-snell"
)

const helloMinBudget = 85 + 1 + saltLen + snell.HeaderCipherLen

type helloRecordCodec struct {
	psk     []byte
	profile *Profile
	prefix  *helloPrefixCodec
}

func newHelloRecordCodec(psk []byte) *helloRecordCodec {
	return &helloRecordCodec{psk: append([]byte(nil), psk...), profile: NewProfile(psk), prefix: newHelloPrefixCodec(psk)}
}

func (c *helloRecordCodec) header(head []byte) (paddingLen, payloadLen int, err error) {
	if len(head) < c.prefix.PrefixSize()+snell.HeaderCipherLen {
		return 0, 0, fmt.Errorf("incomplete first shaped header")
	}
	salt := c.profile.extractSalt(head[:c.profile.saltBlockLen])
	aead, err := snell.NewAEAD(snell.DeriveKey(c.psk, salt[:]))
	if err != nil {
		return 0, 0, err
	}
	prefix := head[c.profile.saltBlockLen:c.prefix.PrefixSize()]
	plain, err := aead.Open(nil, make([]byte, snell.NonceLen), head[c.prefix.PrefixSize():c.prefix.PrefixSize()+snell.HeaderCipherLen], prefix)
	if err != nil {
		return 0, 0, fmt.Errorf("authenticate first shaped header: %w", err)
	}
	if plain[0] != snell.HeaderVersion {
		return 0, 0, fmt.Errorf("invalid shaped header version")
	}
	return int(binary.BigEndian.Uint16(plain[3:5])), int(binary.BigEndian.Uint16(plain[5:7])), nil
}

// budget is the maximum encoded extension payload, excluding the85-byte carrier
// envelope. Mode1 compacts a whole record; mode0 preserves a prefix when the
// ciphertext itself is too large. Any unconsumed original suffix is sent intact.
func (c *helloRecordCodec) Pack(original []byte, budget int) (packed []byte, consumed int, mode int, err error) {
	if budget < 1+saltLen+snell.HeaderCipherLen {
		return nil, 0, 0, fmt.Errorf("carrier budget too small")
	}
	if len(original) < c.prefix.PrefixSize() {
		return nil, 0, 0, fmt.Errorf("short original prefix")
	}
	// Verify all omitted prefix bytes even when we use the fallback.
	if _, err = c.prefix.Pack(original[:c.prefix.PrefixSize()]); err != nil {
		return nil, 0, 0, err
	}
	headLen := c.prefix.PrefixSize() + snell.HeaderCipherLen
	if len(original) >= headLen {
		padSize, dataSize, e := c.header(original[:headLen])
		if e != nil {
			return nil, 0, 0, e
		}
		cipherSize := dataSize
		if dataSize > 0 {
			cipherSize += snell.AEADTagLen
		}
		originalSize := headLen + padSize + cipherSize
		packedSize := 1 + saltLen + snell.HeaderCipherLen + cipherSize
		if originalSize <= len(original) && packedSize <= budget {
			body := append([]byte(nil), original[headLen:originalSize]...)
			padding, ciphertext := body[:padSize], body[padSize:]
			if dataSize > 0 {
				c.profile.mixPaddingPayload(0, padding, ciphertext)
			}
			expected := make([]byte, padSize)
			c.profile.fillPadding(0, expected)
			if !bytes.Equal(padding, expected) {
				return nil, 0, 0, fmt.Errorf("first record padding is not reproducible")
			}
			packedHead, e := c.prefix.Pack(original[:headLen])
			if e != nil {
				return nil, 0, 0, e
			}
			tail := min(len(original)-originalSize, budget-packedSize)
			packed = make([]byte, 0, packedSize+tail)
			packed = append(packed, 1)
			packed = append(packed, packedHead...)
			packed = append(packed, ciphertext...)
			packed = append(packed, original[originalSize:originalSize+tail]...)
			if originalSize < len(original) {
				multi, take, e := c.packRecords(original, budget)
				if e != nil {
					return nil, 0, 0, e
				}
				if take > originalSize+tail {
					return multi, take, 2, nil
				}
			}
			return packed, originalSize + tail, 1, nil
		}
	}
	// A large first ciphertext stays byte-for-byte intact; save only the already
	// verified deterministic prefix. The explicit mode byte is included in budget.
	consumed = min(len(original), budget-1+c.prefix.SavedBytes())
	if consumed < c.prefix.PrefixSize() {
		return nil, 0, 0, fmt.Errorf("prefix does not fit carrier budget")
	}
	p, e := c.prefix.Pack(original[:consumed])
	if e != nil {
		return nil, 0, 0, e
	}
	return append([]byte{0}, p...), consumed, 0, nil
}

func (c *helloRecordCodec) Unpack(packed []byte) ([]byte, error) {
	if len(packed) < 1 {
		return nil, fmt.Errorf("missing record codec mode")
	}
	if packed[0] == 0 {
		return c.prefix.Unpack(packed[1:])
	}
	if packed[0] == 2 {
		return c.unpackRecords(packed)
	}
	if packed[0] != 1 {
		return nil, fmt.Errorf("unknown record codec mode")
	}
	headSize := saltLen + snell.HeaderCipherLen
	if len(packed) < 1+headSize {
		return nil, fmt.Errorf("truncated packed header")
	}
	head, err := c.prefix.Unpack(packed[1 : 1+headSize])
	if err != nil {
		return nil, err
	}
	padSize, dataSize, err := c.header(head)
	if err != nil {
		return nil, err
	}
	cipherSize := dataSize
	if dataSize > 0 {
		cipherSize += snell.AEADTagLen
	}
	if len(packed) < 1+headSize+cipherSize {
		return nil, fmt.Errorf("truncated packed payload ciphertext")
	}
	// Authenticated16-bit lengths cap expansion at about128KiB. No unauthenticated
	// declared length is used to allocate the reconstructed record.
	out := make([]byte, len(head)+padSize+cipherSize)
	copy(out, head)
	padding := out[len(head) : len(head)+padSize]
	ciphertext := out[len(head)+padSize:]
	c.profile.fillPadding(0, padding)
	copy(ciphertext, packed[1+headSize:1+headSize+cipherSize])
	if dataSize > 0 {
		c.profile.mixPaddingPayload(0, padding, ciphertext)
	}
	out = append(out, packed[1+headSize+cipherSize:]...)
	return out, nil
}
