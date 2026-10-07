package snellv6

import (
    "crypto/cipher"
    "encoding/binary"
    "io"
    snell "github.com/sagernet/sing-snell"
    "github.com/sagernet/sing/common/buf"
    E "github.com/sagernet/sing/common/exceptions"
)

// Limit header read-ahead after a large frame; body reads stay unrestricted.
// Keep bufio's own short-read/error handling and buffered bytes intact.
type adaptiveShapedInput struct {
    io.Reader
    capacity int
    maximum int
}
func (r *adaptiveShapedInput) Read(p []byte) (int, error) {
    if r.maximum > 0 && len(p) > r.maximum { p = p[:r.maximum] }
    return r.Reader.Read(p)
}

type coalescedShapedReader struct {
	baseReader
    controller *adaptiveShapedInput
    previousPayload int
	psk     []byte
	profile *Profile
	cipher  cipher.AEAD
	nonce   []byte
	seq     uint32
	head    []byte
}

func newCoalescedShapedReader(upstream io.Reader, psk []byte, profile *Profile) *coalescedShapedReader {
	r := &coalescedShapedReader{
		psk: psk, profile: profile, nonce: make([]byte, snell.NonceLen),
		head: make([]byte, profile.recordPrefixMax+snell.HeaderCipherLen),
	}
	r.upstream = upstream
	r.readFunc = r.read
	return r
}

func (r *coalescedShapedReader) read() (*buf.Buffer, error) {
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
	head := r.head[:prefixLen+snell.HeaderCipherLen]
    if r.controller != nil && r.previousPayload >= 2*r.controller.capacity {
        r.controller.maximum = len(head)
    }
	_, err := io.ReadFull(r.upstream, head)
    if r.controller != nil { r.controller.maximum = 0 }
	if err != nil {
		return nil, err
	}
	prefix := head[:prefixLen]
	headerCipher := head[prefixLen:]
	_, err = r.cipher.Open(headerCipher[:0], r.nonce, headerCipher, prefix)
	if err != nil {
		return nil, E.Cause(err, "open shaped header")
	}
	snell.IncreaseNonce(r.nonce)
	if headerCipher[0] != snell.HeaderVersion {
		return nil, E.Extend(snell.ErrBadVersion, headerCipher[0])
	}
	// Surge 6.7.0 (11520): FUN_100013abc: default-shaped reader ignores the two reserved header bytes.
	paddingLen := int(binary.BigEndian.Uint16(headerCipher[3:5]))
	payloadLen := int(binary.BigEndian.Uint16(headerCipher[5:7]))
    r.previousPayload = payloadLen
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

	// Padding and ciphertext are adjacent on the wire. Reserve both in the
	// returned buffer, then advance past padding instead of copying payload.
	body := r.readWaitOptions.NewBufferSize(paddingLen + payloadLen + snell.AEADTagLen)
	_, err = body.ReadFullFrom(r.upstream, paddingLen+payloadLen+snell.AEADTagLen)
	if err != nil {
		body.Release()
		return nil, err
	}
	paddingBytes := body.To(paddingLen)
	body.Advance(paddingLen)
	payloadCipher := body.Bytes()
	r.profile.mixPaddingPayload(seq, paddingBytes, payloadCipher)
	_, err = r.cipher.Open(payloadCipher[:0], r.nonce, payloadCipher, paddingBytes)
	if err != nil {
		body.Release()
		return nil, E.Cause(err, "open shaped payload")
	}
	snell.IncreaseNonce(r.nonce)
	body.Truncate(payloadLen)
	r.readWaitOptions.PostReturn(body)
	return body, nil
}
