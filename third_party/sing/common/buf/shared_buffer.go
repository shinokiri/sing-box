package buf

import "sync/atomic"

type sharedBufferStorage struct {
	data []byte
	refs atomic.Int32
	pooled bool
}


// SharedSlice creates an independently indexed view of the raw range [from, to), indexed from the beginning of this handle,
// including any headroom before Bytes().
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
