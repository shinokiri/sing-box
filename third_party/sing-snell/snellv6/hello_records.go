package snellv6

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"

	snell "github.com/sagernet/sing-snell"
)

// Mode 2: mode, record count, salt positions, then each authenticated header
// and unmixed payload ciphertext. Any remaining bytes are an unchanged suffix.
// The count and total expansion are bounded independently of authenticated
// per-record lengths. No application payload is decrypted or re-encrypted.
const (
	helloMaxCompactRecords = 32
	helloMaxExpandedBytes  = 256 << 10
)

type helloRecordState struct {
	aead  cipher.AEAD
	nonce []byte
}

func (c *helloRecordCodec) recordState(firstPrefix []byte) (*helloRecordState, error) {
	salt := c.profile.extractSalt(firstPrefix[:c.profile.saltBlockLen])
	aead, err := snell.NewAEAD(snell.DeriveKey(c.psk, salt[:]))
	if err != nil {
		return nil, err
	}
	return &helloRecordState{aead: aead, nonce: make([]byte, snell.NonceLen)}, nil
}

func (s *helloRecordState) open(header, prefix []byte) (paddingLen, cipherLen int, err error) {
	plain, err := s.aead.Open(nil, s.nonce, header, prefix)
	if err != nil {
		return 0, 0, fmt.Errorf("authenticate shaped header: %w", err)
	}
	if len(plain) != snell.HeaderPlainLen || plain[0] != snell.HeaderVersion {
		return 0, 0, fmt.Errorf("invalid shaped header")
	}
	snell.IncreaseNonce(s.nonce)
	paddingLen = int(binary.BigEndian.Uint16(plain[3:5]))
	cipherLen = int(binary.BigEndian.Uint16(plain[5:7]))
	if cipherLen > 0 {
		cipherLen += snell.AEADTagLen
		// The existing writer consumes a nonce for nonempty payloads only.
		snell.IncreaseNonce(s.nonce)
	}
	return
}

func (c *helloRecordCodec) packRecords(original []byte, budget int) ([]byte, int, error) {
	firstPrefix := original[:c.prefix.PrefixSize()]
	salt, err := c.prefix.Pack(firstPrefix)
	if err != nil {
		return nil, 0, err
	}
	state, err := c.recordState(firstPrefix)
	if err != nil {
		return nil, 0, err
	}
	packed := append([]byte{2, 0}, salt...)
	at, count := 0, 0
	for count < helloMaxCompactRecords {
		prefixLen := c.profile.recordPrefixLen(uint32(count))
		saltSize := 0
		if count == 0 {
			saltSize = c.profile.saltBlockLen
		}
		headEnd := at + saltSize + prefixLen + snell.HeaderCipherLen
		if headEnd > len(original) || len(packed)+snell.HeaderCipherLen > budget {
			break
		}
		prefix := original[at+saltSize : headEnd-snell.HeaderCipherLen]
		expectedPrefix := make([]byte, prefixLen)
		c.profile.fillPadding(uint32(count), expectedPrefix)
		if !bytes.Equal(prefix, expectedPrefix) {
			return nil, 0, fmt.Errorf("record %d prefix is not reproducible", count)
		}
		header := original[headEnd-snell.HeaderCipherLen : headEnd]
		padSize, cipherSize, err := state.open(header, prefix)
		if err != nil {
			return nil, 0, err
		}
		end := headEnd + padSize + cipherSize
		if end > len(original) || end > helloMaxExpandedBytes || len(packed)+snell.HeaderCipherLen+cipherSize > budget {
			break
		}
		body := append([]byte(nil), original[headEnd:end]...)
		padding, ciphertext := body[:padSize], body[padSize:]
		if cipherSize > 0 {
			c.profile.mixPaddingPayload(uint32(count), padding, ciphertext)
		}
		expectedPadding := make([]byte, padSize)
		c.profile.fillPadding(uint32(count), expectedPadding)
		if !bytes.Equal(padding, expectedPadding) {
			return nil, 0, fmt.Errorf("record %d padding is not reproducible", count)
		}
		packed = append(packed, header...)
		packed = append(packed, ciphertext...)
		at, count = end, count+1
	}
	if count < 2 {
		return nil, 0, nil
	}
	packed[1] = byte(count)
	tail := min(len(original)-at, budget-len(packed), helloMaxExpandedBytes-at)
	packed = append(packed, original[at:at+tail]...)
	return packed, at + tail, nil
}

func (c *helloRecordCodec) unpackRecords(packed []byte) ([]byte, error) {
	if len(packed) < 2+saltLen || len(packed) > 4096 {
		return nil, fmt.Errorf("invalid multi-record encoding size")
	}
	count := int(packed[1])
	if count < 2 || count > helloMaxCompactRecords {
		return nil, fmt.Errorf("invalid compact record count")
	}
	firstPrefix, err := c.prefix.Unpack(packed[2 : 2+saltLen])
	if err != nil {
		return nil, err
	}
	state, err := c.recordState(firstPrefix)
	if err != nil {
		return nil, err
	}
	var out []byte
	at := 2 + saltLen
	for seq := 0; seq < count; seq++ {
		var fullPrefix, prefix []byte
		if seq == 0 {
			fullPrefix = firstPrefix
			prefix = fullPrefix[c.profile.saltBlockLen:]
		} else {
			fullPrefix = make([]byte, c.profile.recordPrefixLen(uint32(seq)))
			c.profile.fillPadding(uint32(seq), fullPrefix)
			prefix = fullPrefix
		}
		if at+snell.HeaderCipherLen > len(packed) {
			return nil, fmt.Errorf("truncated record %d header", seq)
		}
		header := packed[at : at+snell.HeaderCipherLen]
		padSize, cipherSize, err := state.open(header, prefix)
		if err != nil {
			return nil, err
		}
		at += snell.HeaderCipherLen
		if at+cipherSize > len(packed) {
			return nil, fmt.Errorf("truncated record %d ciphertext", seq)
		}
		size := len(fullPrefix) + snell.HeaderCipherLen + padSize + cipherSize
		if len(out)+size > helloMaxExpandedBytes {
			return nil, fmt.Errorf("expanded records exceed limit")
		}
		out = append(out, fullPrefix...)
		out = append(out, header...)
		start := len(out)
		out = append(out, make([]byte, padSize+cipherSize)...)
		padding, ciphertext := out[start:start+padSize], out[start+padSize:]
		c.profile.fillPadding(uint32(seq), padding)
		copy(ciphertext, packed[at:at+cipherSize])
		if cipherSize > 0 {
			c.profile.mixPaddingPayload(uint32(seq), padding, ciphertext)
		}
		at += cipherSize
	}
	if len(out)+len(packed)-at > helloMaxExpandedBytes {
		return nil, fmt.Errorf("expanded suffix exceeds limit")
	}
	out = append(out, packed[at:]...)
	return out, nil
}
