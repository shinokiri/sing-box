// This file is copied into the pinned sing dependency by prepare_shared.py.
// It is an isolated experiment, not part of the application's build.
package buf

import "sync/atomic"

type sharedBufferStorage struct {
	data []byte
	refs atomic.Int32
	pooled bool
}

var studySharedBytes atomic.Int64
var studySharedBlocks atomic.Int64

// SharedSlice creates an independently indexed view of a raw buffer range.
// Creation and mutation of the same Buffer handle must be serialized. Distinct
// views may be released concurrently. The caller must never overwrite a range
// while another view owns it, or create views of externally mutable storage.
// A three-index slice prevents Reset or OverCap from exposing adjacent frames.
func (b *Buffer) SharedSlice(from, to int) *Buffer {
	if from < 0 || to < from || to > b.capacity {
		panic("shared buffer slice out of range")
	}
	if b.shared == nil {
		s := &sharedBufferStorage{data: b.data, pooled: b.managed}
		s.refs.Store(1)
		b.shared = s
		b.managed = true
		studySharedBytes.Add(int64(cap(s.data)))
		studySharedBlocks.Add(1)
	}
	b.shared.refs.Add(1)
	return &Buffer{
		data: b.data[from:to:to], end: to-from, capacity: to-from,
		managed: true, shared: b.shared,
	}
}

// HasSharedViews is useful only while the caller exclusively owns this handle.
// Releasing other handles can turn true into false; they cannot add references
// without retaining an existing handle. The receive owner alone creates views.
func (b *Buffer) HasSharedViews() bool {
	return b.shared != nil && b.shared.refs.Load() > 1
}

func StudySharedStorage() (bytes, blocks int64) {
	return studySharedBytes.Load(), studySharedBlocks.Load()
}

func (b *Buffer) StudyUsesSharedStorage() bool { return b.shared != nil }
