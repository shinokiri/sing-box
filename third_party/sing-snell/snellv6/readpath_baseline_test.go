// Generated baseline from installed release c99d7779; study only.
package snellv6

import (
    "crypto/cipher"
    "encoding/binary"
    "io"
    snell "github.com/sagernet/sing-snell"
    "github.com/sagernet/sing/common/buf"
    E "github.com/sagernet/sing/common/exceptions"
)

type baselineShapedReader struct {
	baseReader
	psk     []byte
	profile *Profile
	cipher  cipher.AEAD
	nonce   []byte
	seq     uint32
}

func newBaselineShapedReader(upstream io.Reader, psk []byte, profile *Profile) *baselineShapedReader {
	r := &baselineShapedReader{psk: psk, profile: profile, nonce: make([]byte, snell.NonceLen)}
	r.upstream = upstream
	r.readFunc = r.read
	return r
}

func (r *baselineShapedReader) read() (*buf.Buffer, error) {
	if r.cipher == nil {
		block := make([]byte, r.profile.saltBlockLen)
		_, err := io.ReadFull(r.upstream, block)
		if err != nil {
			return nil, err
		}
		salt := r.profile.extractSalt(block)
		aead, err := snell.NewAEAD(snell.DeriveKey(r.psk, salt[:]))
		if err != nil {
			return nil, err
		}
		r.cipher = aead
	}

	prefixLen := r.profile.recordPrefixLen(r.seq)
	head := buf.NewSize(prefixLen + snell.HeaderCipherLen)
	_, err := head.ReadFullFrom(r.upstream, prefixLen+snell.HeaderCipherLen)
	if err != nil {
		head.Release()
		return nil, err
	}
	prefix := head.To(prefixLen)
	headerCipher := head.Range(prefixLen, prefixLen+snell.HeaderCipherLen)
	_, err = r.cipher.Open(headerCipher[:0], r.nonce, headerCipher, prefix)
	if err != nil {
		head.Release()
		return nil, E.Cause(err, "open shaped header")
	}
	snell.IncreaseNonce(r.nonce)
	if headerCipher[0] != snell.HeaderVersion {
		head.Release()
		return nil, E.Extend(snell.ErrBadVersion, headerCipher[0])
	}
	// Surge 6.7.0 (11520): FUN_100013abc: default-shaped reader ignores the two reserved header bytes.
	paddingLen := int(binary.BigEndian.Uint16(headerCipher[3:5]))
	payloadLen := int(binary.BigEndian.Uint16(headerCipher[5:7]))
	head.Release()
	seq := r.seq
	r.seq++

	if payloadLen == 0 {
		if paddingLen > 0 {
			discard := buf.NewSize(paddingLen)
			_, err = discard.ReadFullFrom(r.upstream, paddingLen)
			discard.Release()
			if err != nil {
				return nil, err
			}
		}
		return nil, io.EOF
	}

	var padding *buf.Buffer
	if paddingLen > 0 {
		padding = buf.NewSize(paddingLen)
		_, err = padding.ReadFullFrom(r.upstream, paddingLen)
		if err != nil {
			padding.Release()
			return nil, err
		}
	}
	body := r.readWaitOptions.NewBufferSize(payloadLen + snell.AEADTagLen)
	_, err = body.ReadFullFrom(r.upstream, payloadLen+snell.AEADTagLen)
	if err != nil {
		if padding != nil {
			padding.Release()
		}
		body.Release()
		return nil, err
	}
	var paddingBytes []byte
	if padding != nil {
		paddingBytes = padding.Bytes()
	}
	payloadCipher := body.Bytes()
	r.profile.mixPaddingPayload(seq, paddingBytes, payloadCipher)
	_, err = r.cipher.Open(payloadCipher[:0], r.nonce, payloadCipher, paddingBytes)
	if padding != nil {
		padding.Release()
	}
	if err != nil {
		body.Release()
		return nil, E.Cause(err, "open shaped payload")
	}
	snell.IncreaseNonce(r.nonce)
	body.Truncate(payloadLen)
	r.readWaitOptions.PostReturn(body)
	return body, nil
}
