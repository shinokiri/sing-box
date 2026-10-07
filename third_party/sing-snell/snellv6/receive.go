package snellv6

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"sync/atomic"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/internal/reuse"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

const (
	receiveInitialWindow       = 4096
	receiveMaxWindow           = 65536
	receiveClosed        int64 = 1 << 62
)

// receiveLifecycle lets a physical connection close without releasing memory
// still used by a read. The last operation releases it when Close raced with a
// read, including a read that is still constructing its record reader.
type receiveLifecycle struct{ state atomic.Int64 }

func (l *receiveLifecycle) begin() bool {
	for {
		state := l.state.Load()
		if state&receiveClosed != 0 {
			return false
		}
		if l.state.CompareAndSwap(state, state+1) {
			return true
		}
	}
}

func (l *receiveLifecycle) end(release func()) {
	if l.state.Add(-1) == receiveClosed {
		release()
	}
}

func (l *receiveLifecycle) close(release func()) {
	for {
		state := l.state.Load()
		if state&receiveClosed != 0 {
			return
		}
		if l.state.CompareAndSwap(state, state|receiveClosed) {
			if state == 0 {
				release()
			}
			return
		}
	}
}

func releaseResponseReader(reader reuse.RecordReader) {
	if owned, ok := reader.(interface{ releaseReceive() }); ok {
		owned.releaseReceive()
	} else if reader != nil {
		reader.ReleaseCache()
	}
}

// Only client TCP responses use the buffered receive path. Packet and server
// readers keep their existing constructors and buffer lifetime contracts.
func readFirstResponse(conn io.Reader, mode Mode, psk []byte, profile *Profile, options N.ReadWaitOptions) (reuse.RecordReader, *buf.Buffer, error) {
	if mode != ModeDefault {
		return readFirstRecord(conn, mode, psk, profile, options)
	}
	r := newBufferedShapedReader(conn, psk, profile)
	r.InitializeReadWaiter(options)
	record, err := r.ReadRecord()
	if err != nil {
		r.releaseReceive()
		return nil, nil, err
	}
	return r, record, nil
}

// bufferedShapedReader batches available records without waiting for another
// record. A drained block can be transferred whole; other large records may
// use bounded shared views. Small records are copied so delayed consumers do
// not pin a large allocation for a few bytes. Published ranges are immutable
// to this reader, including the downstream writer's requested header space.
type bufferedShapedReader struct {
	baseReader
	psk              []byte
	profile          *Profile
	cipher           cipher.AEAD
	nonce            []byte
	seq              uint32
	block            *buf.Buffer
	position         int
	pendingErr       error
	readAhead        int
	transferCapacity int
	viewFence        int
}

func newBufferedShapedReader(input io.Reader, psk []byte, profile *Profile) *bufferedShapedReader {
	r := &bufferedShapedReader{psk: psk, profile: profile, nonce: make([]byte, snell.NonceLen), readAhead: receiveInitialWindow}
	r.upstream = input
	r.readFunc = r.read
	return r
}

func (r *bufferedShapedReader) capacityFor(required int) int {
	return (max(required+r.readWaitOptions.FrontHeadroom, r.readAhead) + 4095) &^ 4095
}

func (r *bufferedShapedReader) ensure(required int) error {
	front := r.readWaitOptions.FrontHeadroom
	if r.block == nil {
		if r.pendingErr != nil {
			return r.pendingErr
		}
		r.block = buf.NewSize(max(r.capacityFor(required), r.transferCapacity))
		r.block.Resize(0, front)
		r.position = front
		r.viewFence = 0
	}
	available := r.block.Len() - r.position
	if available >= required {
		return nil
	}
	if available == 0 && r.position > 0 {
		if !receiveHasViews(r.block) && r.block.Cap() >= front {
			r.block.Resize(0, front)
		} else {
			capacity := max(r.block.Cap(), r.capacityFor(required))
			r.block.Release()
			r.block = buf.NewSize(capacity)
			r.block.Resize(0, front)
		}
		r.position = front
		r.viewFence = 0
	}
	minimum := max(required+front, r.readAhead)
	if r.block.Cap()-r.position < required || r.block.Cap() < minimum {
		if !receiveHasViews(r.block) && r.block.Cap() >= minimum {
			tail := r.block.Bytes()[r.position:]
			r.block.Resize(0, front+available)
			copy(r.block.Bytes()[front:], tail)
		} else {
			next := buf.NewSize(max(r.block.Cap(), r.capacityFor(required)))
			next.Resize(0, front)
			next.Write(r.block.Bytes()[r.position:])
			r.block.Release()
			r.block = next
		}
		r.position = front
		r.viewFence = 0
	}
	emptyReads := 0
	for r.block.Len()-r.position < required {
		if r.pendingErr != nil {
			if errors.Is(r.pendingErr, io.EOF) && r.block.Len() > r.position {
				return io.ErrUnexpectedEOF
			}
			return r.pendingErr
		}
		remaining := required - (r.block.Len() - r.position)
		limit := remaining
		window := r.readAhead
		prefetch := required <= window
		if prefetch {
			limit = max(limit, window)
		}
		space := r.block.FreeBytes()
		space = space[:min(len(space), limit)]
		n, err := r.upstream.Read(space)
		r.block.Extend(n)
		if prefetch && len(space) >= window/2 && n == len(space) {
			r.readAhead = min(receiveMaxWindow, window*4)
		}
		if err != nil {
			r.pendingErr = err
		}
		if n == 0 && err == nil {
			emptyReads++
			if emptyReads >= 100 {
				return io.ErrNoProgress
			}
		} else {
			emptyReads = 0
		}
	}
	return nil
}

func (r *bufferedShapedReader) read() (*buf.Buffer, error) {
	if r.cipher == nil {
		if err := r.ensure(r.profile.saltBlockLen); err != nil {
			return nil, err
		}
		salt := r.profile.extractSalt(r.block.Bytes()[r.position : r.position+r.profile.saltBlockLen])
		aead, err := snell.NewAEAD(snell.DeriveKey(r.psk, salt[:]))
		if err != nil {
			return nil, err
		}
		r.cipher = aead
		r.position += r.profile.saltBlockLen
	}
	prefixLen := r.profile.recordPrefixLen(r.seq)
	headLen := prefixLen + snell.HeaderCipherLen
	if err := r.ensure(headLen); err != nil {
		return nil, err
	}
	head := r.block.Bytes()[r.position : r.position+headLen]
	headerCipher := head[prefixLen:]
	if _, err := r.cipher.Open(headerCipher[:0], r.nonce, headerCipher, head[:prefixLen]); err != nil {
		return nil, E.Cause(err, "open shaped header")
	}
	snell.IncreaseNonce(r.nonce)
	if headerCipher[0] != snell.HeaderVersion {
		return nil, E.Extend(snell.ErrBadVersion, headerCipher[0])
	}
	// The shaped protocol ignores the two reserved header bytes.
	paddingLen := int(binary.BigEndian.Uint16(headerCipher[3:5]))
	payloadLen := int(binary.BigEndian.Uint16(headerCipher[5:7]))
	seq := r.seq
	r.seq++
	frameLen := headLen + paddingLen
	if payloadLen > 0 {
		frameLen += payloadLen + snell.AEADTagLen
	}
	if err := r.ensure(frameLen); err != nil {
		return nil, err
	}
	start := r.position
	r.position += frameLen
	if payloadLen == 0 {
		r.releaseDrainedBlock()
		r.readAhead = receiveInitialWindow
		r.transferCapacity = 0
		return nil, io.EOF
	}
	frame := r.block.Bytes()[start:r.position]
	padding := frame[headLen : headLen+paddingLen]
	payload := frame[headLen+paddingLen:]
	r.profile.mixPaddingPayload(seq, padding, payload)
	if _, err := r.cipher.Open(payload[:0], r.nonce, payload, padding); err != nil {
		return nil, E.Cause(err, "open shaped payload")
	}
	snell.IncreaseNonce(r.nonce)
	payloadStart := start + headLen + paddingLen
	if !receiveHasViews(r.block) && r.position == r.block.Len() && payloadLen > 2048 && payloadLen >= r.block.Cap()/4 &&
		payloadStart >= r.readWaitOptions.FrontHeadroom && r.block.Cap()-(payloadStart+payloadLen) >= r.readWaitOptions.RearHeadroom {
		body := r.block
		r.transferCapacity = body.Cap()
		r.block = nil
		r.position = 0
		r.viewFence = 0
		body.Resize(payloadStart, payloadLen)
		return body, nil
	}
	if receiveSharing && payloadLen > 2048 && payloadLen >= r.block.Cap()/8 && r.readWaitOptions.RearHeadroom <= snell.AEADTagLen {
		if !receiveHasViews(r.block) {
			r.viewFence = 0
		}
		viewStart := payloadStart - r.readWaitOptions.FrontHeadroom
		if viewStart >= r.viewFence {
			body := receiveSlice(r.block, viewStart, r.position)
			body.Advance(payloadStart - viewStart)
			body.Truncate(payloadLen)
			r.viewFence = r.position
			return body, nil
		}
	}
	body := r.readWaitOptions.NewBufferSize(payloadLen)
	body.Write(payload[:payloadLen])
	r.readWaitOptions.PostReturn(body)
	return body, nil
}

func (r *bufferedShapedReader) releaseDrainedBlock() {
	if r.block != nil && r.position == r.block.Len() {
		r.block.Release()
		r.block = nil
		r.position = 0
	}
}

// Called only after physical-close read operations have quiesced. Logical EOF
// leaves prefetched bytes belonging to the next reused connection intact.
func (r *bufferedShapedReader) releaseReceive() {
	r.baseReader.ReleaseCache()
	if r.block != nil {
		r.block.Release()
		r.block = nil
	}
	r.position = 0
}
