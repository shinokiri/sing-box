//go:build shared_receive_study

package snellv6

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"flag"
	"io"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
)

var studyBlockSize = flag.Int("study-block-size", 4096, "initial shared receive block capacity")
var studySharedReadAhead = flag.Int("study-shared-read-ahead", 4096, "maximum extra small-field receive window")

func init() {
	studyPolicies = append(studyPolicies, "shared", "bounded")
	studySharedFactory = func(policy string, input io.Reader, profile *Profile) (studyRecordReader, func(cipher.AEAD)) {
		r := newSharedShapedReader(input, studyPSK, profile)
		if policy == "bounded" { r.enableBounded() }
		return r, func(aead cipher.AEAD) { r.cipher = aead; clear(r.nonce); r.seq = 0 }
	}
}

// Experimental reader: no production constructor selects it. Input belongs to
// one physical session, including unread bytes after a logical EOF. Calls that
// mutate the reader must be serialized, matching the existing record reader.
type sharedShapedReader struct {
	baseReader
	psk []byte
	profile *Profile
	cipher cipher.AEAD
	nonce []byte
	seq uint32
	block *buf.Buffer
	position int
	pendingErr error
	copiedBytes uint64
	sharedFrames uint64
	copiedFrames uint64
	peakCapacity int
	bounded bool
	readAhead int
	viewFence int
}

func (r *sharedShapedReader) enableBounded() {
	r.bounded = true
	r.readAhead = min(4096, max(256, *studySharedReadAhead))
}

func newSharedShapedReader(input io.Reader, psk []byte, profile *Profile) *sharedShapedReader {
	r := &sharedShapedReader{psk: psk, profile: profile, nonce: make([]byte, snell.NonceLen)}
	r.upstream = input
	r.readFunc = r.read
	return r
}

func sharedCapacity(required int) int {
	size := max(256, *studyBlockSize)
	for size < required { size *= 2 }
	return size
}

func (r *sharedShapedReader) capacityFor(required int) int {
	if !r.bounded { return sharedCapacity(required) }
	// Round modestly instead of doubling a nearly 64 KiB record to 128 KiB.
	return (max(required+r.readWaitOptions.FrontHeadroom, r.readAhead) + 4095) &^ 4095
}

// ensure waits for only the current protocol field/record, never a full block.
// It reads already-available following records when space permits. Published
// views are immutable from the receiver's perspective; only unconsumed bytes
// may move when the block ends or grows. No prediction uses the preceding frame.
func (r *sharedShapedReader) ensure(required int) error {
	front := 0
	if r.bounded { front = r.readWaitOptions.FrontHeadroom }
	if r.block == nil {
		r.block = buf.NewSize(r.capacityFor(required))
		r.block.Resize(0, front)
		r.position = front
		r.viewFence = 0
		r.peakCapacity = max(r.peakCapacity, r.block.Cap())
	}
	available := r.block.Len() - r.position
	if available >= required { return nil }
	if available == 0 && r.position > 0 {
		if !r.block.HasSharedViews() && r.block.Cap() >= front {
			r.block.Resize(0, front)
			r.position = front
			r.viewFence = 0
		} else if r.bounded {
			// Start a new owned region before consuming the next header. Keep
			// known useful capacity so a retained previous frame does not force
			// prefetched large payloads to relocate once their size is known.
			capacity := max(r.block.Cap(), r.capacityFor(required))
			r.block.Release()
			r.block = buf.NewSize(capacity)
			r.block.Resize(0, front)
			r.position = front
			r.viewFence = 0
			r.peakCapacity = max(r.peakCapacity, capacity)
		}
	}
	minimum := required
	if r.bounded { minimum = max(required+front, r.readAhead) }
	if r.block.Cap() - r.position < required || r.block.Cap() < minimum {
		if !r.block.HasSharedViews() && r.block.Cap() >= minimum {
			tail := r.block.Bytes()[r.position:]
			r.block.Resize(0, front+available)
			copy(r.block.Bytes()[front:], tail)
		} else {
			next := buf.NewSize(max(r.block.Cap(), r.capacityFor(required)))
			next.Resize(0, front)
			next.Write(r.block.Bytes()[r.position:])
			r.block.Release()
			r.block = next
			r.peakCapacity = max(r.peakCapacity, next.Cap())
		}
		r.copiedBytes += uint64(available)
		r.position = front
		r.viewFence = 0
	}
	emptyReads := 0
	for r.block.Len() - r.position < required {
		if r.pendingErr != nil {
			if errors.Is(r.pendingErr, io.EOF) && r.block.Len() > r.position { return io.ErrUnexpectedEOF }
			return r.pendingErr
		}
		remaining := required - (r.block.Len() - r.position)
		limit := remaining
		// A known large record is read exactly to its end, allowing a drained
		// block to reset without moving the next record. Small fields/records
		// can still batch whatever is currently available, without waiting.
		window := *studySharedReadAhead
		if r.bounded { window = r.readAhead }
		prefetch := required <= window
		if prefetch { limit = max(limit, window) }
		space := r.block.FreeBytes()
		space = space[:min(len(space), limit)]
		n, err := r.upstream.Read(space)
		r.block.Extend(n)
		// Only a filled, substantial prefetch region grows the future window.
		// Short isolated replies stay small. No timer, RTT or Wi-Fi state is used.
		if r.bounded && prefetch && len(space) >= window/2 && n == len(space) {
			r.readAhead = min(max(256, *studySharedReadAhead), window*4)
		}
		if err != nil { r.pendingErr = err }
		if n == 0 && err == nil {
			emptyReads++
			if emptyReads >= 100 { return io.ErrNoProgress }
		} else { emptyReads = 0 }
	}
	return nil
}

func (r *sharedShapedReader) read() (*buf.Buffer, error) {
	if r.cipher == nil {
		if err := r.ensure(r.profile.saltBlockLen); err != nil { return nil, err }
		salt := r.profile.extractSalt(r.block.Bytes()[r.position:r.position+r.profile.saltBlockLen])
		aead, err := snell.NewAEAD(snell.DeriveKey(r.psk, salt[:]))
		if err != nil { return nil, err }
		r.cipher = aead
		r.position += r.profile.saltBlockLen
	}
	prefixLen := r.profile.recordPrefixLen(r.seq)
	headLen := prefixLen + snell.HeaderCipherLen
	if err := r.ensure(headLen); err != nil { return nil, err }
	head := r.block.Bytes()[r.position:r.position+headLen]
	headerCipher := head[prefixLen:]
	if _, err := r.cipher.Open(headerCipher[:0], r.nonce, headerCipher, head[:prefixLen]); err != nil {
		return nil, E.Cause(err, "open shared shaped header")
	}
	snell.IncreaseNonce(r.nonce)
	if headerCipher[0] != snell.HeaderVersion { return nil, E.Extend(snell.ErrBadVersion, headerCipher[0]) }
	paddingLen := int(binary.BigEndian.Uint16(headerCipher[3:5]))
	payloadLen := int(binary.BigEndian.Uint16(headerCipher[5:7]))
	seq := r.seq
	r.seq++
	frameLen := headLen + paddingLen
	if payloadLen > 0 { frameLen += payloadLen + snell.AEADTagLen }
	if err := r.ensure(frameLen); err != nil { return nil, err }
	start := r.position
	r.position += frameLen
	if payloadLen == 0 {
		r.releaseDrainedBlock()
		if r.bounded { r.readAhead = min(4096, max(256, *studySharedReadAhead)) }
		return nil, io.EOF
	}
	frame := r.block.Bytes()[start:r.position]
	padding := frame[headLen:headLen+paddingLen]
	payload := frame[headLen+paddingLen:]
	r.profile.mixPaddingPayload(seq, padding, payload)
	if _, err := r.cipher.Open(payload[:0], r.nonce, payload, padding); err != nil {
		return nil, E.Cause(err, "open shared shaped payload")
	}
	snell.IncreaseNonce(r.nonce)
	// Header/padding and the used authentication tag are now private writable
	// headroom. Never expose the following frame as writable rear headroom.
	share := !r.bounded || (payloadLen > 2048 && payloadLen >= r.block.Cap()/8)
	viewStart := start
	payloadStart := start + headLen + paddingLen
	if r.bounded && share {
		// Unpublished/fully released preceding bytes can supply writable
		// packet headroom. Never borrow bytes owned by an earlier live view.
		if !r.block.HasSharedViews() { r.viewFence = 0 }
		viewStart = payloadStart - r.readWaitOptions.FrontHeadroom
		if viewStart < r.viewFence { share = false }
	}
	if share && viewStart >= 0 && r.readWaitOptions.FrontHeadroom <= payloadStart-viewStart && r.readWaitOptions.RearHeadroom <= snell.AEADTagLen {
		body := r.block.SharedSlice(viewStart, r.position)
		body.Advance(payloadStart-viewStart)
		body.Truncate(payloadLen)
		r.viewFence = r.position
		r.sharedFrames++
		return body, nil
	}
	body := r.readWaitOptions.NewBufferSize(payloadLen)
	body.Write(payload[:payloadLen])
	r.readWaitOptions.PostReturn(body)
	r.copiedBytes += uint64(payloadLen)
	r.copiedFrames++
	return body, nil
}

func (r *sharedShapedReader) ReleaseCache() {
	r.baseReader.ReleaseCache()
	r.releaseDrainedBlock()
}

func (r *sharedShapedReader) releaseDrainedBlock() {
	// Releasing a logical connection must not discard prefetched next-session
	// bytes. A drained receive block may be released without touching its views.
	if r.block != nil && r.position == r.block.Len() {
		r.block.Release()
		r.block = nil
		r.position = 0
	}
}

// Only after the transport is closed and reading has quiesced. Production
// session close must gain this lifecycle hook before this can be integrated.
func (r *sharedShapedReader) releaseStudyStorage() {
	r.baseReader.ReleaseCache()
	if r.block != nil { r.block.Release(); r.block = nil }
	r.position = 0
}

func (r *sharedShapedReader) studyMetrics() (copied uint64, capacity int) {
	return r.copiedBytes, r.peakCapacity
}
