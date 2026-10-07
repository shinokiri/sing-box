package buf

import (
	"bytes"
	"sync"
	"sync/atomic"
	"testing"
)

type countingAllocator struct {
	Allocator
	puts atomic.Int32
}

func (a *countingAllocator) Put(data []byte) error {
	a.puts.Add(1)
	return a.Allocator.Put(data)
}

func monitorPuts(t *testing.T) *countingAllocator {
	t.Helper()
	previous := DefaultAllocator
	allocator := &countingAllocator{Allocator: previous}
	DefaultAllocator = allocator
	t.Cleanup(func() { DefaultAllocator = previous })
	return allocator
}

func TestSharedLifetimeAndBounds(t *testing.T) {
	allocator := monitorPuts(t)
	owner := NewSize(4096)
	owner.Write(bytes.Repeat([]byte{0x35}, 4096))
	one := owner.SharedSlice(100, 200)
	two := owner.SharedSlice(200, 300)
	child := one.SharedSlice(10, 20)
	one.Release()
	owner.Release()
	if allocator.puts.Load() != 0 {
		t.Fatal("storage returned while views remained")
	}
	if !bytes.Equal(child.Bytes(), bytes.Repeat([]byte{0x35}, 10)) {
		t.Fatal("child invalidated")
	}
	two.Reset()
	if two.RawCap() != 100 || two.Cap() != 100 {
		t.Fatal("view escaped its range")
	}
	two.Write(bytes.Repeat([]byte{0x77}, 100))
	if child.Byte(0) != 0x35 {
		t.Fatal("sibling overwritten")
	}
	two.Release()
	child.IncRef()
	child.Release()
	if child.Len() != 10 || allocator.puts.Load() != 0 {
		t.Fatal("pinned view released")
	}
	child.DecRef()
	child.Release()
	child.Release()
	if allocator.puts.Load() != 1 {
		t.Fatal("original allocation was not returned exactly once")
	}
}

func TestSharedConcurrentRelease(t *testing.T) {
	allocator := monitorPuts(t)
	owner := NewSize(8192)
	owner.Extend(8192)
	views := make([]*Buffer, 128)
	for i := range views {
		views[i] = owner.SharedSlice(i*64, (i+1)*64)
	}
	var wg sync.WaitGroup
	for i, view := range views {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range view.Bytes() {
				view.SetByte(j, byte(i))
			}
			view.Release()
		}()
	}
	owner.Release()
	wg.Wait()
	if allocator.puts.Load() != 1 {
		t.Fatal("concurrent releases did not return storage exactly once")
	}
}

func TestSharedBufferOperations(t *testing.T) {
	for _, pooled := range []bool{false, true} {
		t.Run(map[bool]string{false: "external", true: "pooled"}[pooled], func(t *testing.T) {
			allocator := monitorPuts(t)
			var owner *Buffer
			if pooled {
				owner = NewSize(4096)
				owner.Extend(4096)
			} else {
				owner = As(make([]byte, 4096))
			}
			copy(owner.Bytes()[128:384], bytes.Repeat([]byte{0x51}, 256))
			view := owner.SharedSlice(128, 384)
			owner.Release()
			view.Advance(72)
			view.Truncate(64)
			clone := view.ToOwned()
			if clone.Start() != view.Start() || clone.FreeLen() != view.FreeLen() || !bytes.Equal(clone.Bytes(), view.Bytes()) {
				t.Fatal("ToOwned lost layout or bytes")
			}
			view.Reserve(16)
			view.OverCap(16)
			view.Reset()
			if view.Cap() != 256 || cap(view.Bytes()) != 256 {
				t.Fatal("reset escaped view")
			}
			view.Write(bytes.Repeat([]byte{0x62}, 256))
			if clone.Byte(0) != 0x51 {
				t.Fatal("ToOwned still shared payload")
			}
			view.Release()
			clone.Release()
			want := int32(1)
			if pooled {
				want++
			}
			if allocator.puts.Load() != want {
				t.Fatal("external storage returned to pool or owned storage leaked")
			}
		})
	}
}

func TestSharedRangeRejectsEscape(t *testing.T) {
	owner := NewSize(4096)
	defer owner.Release()
	view := owner.SharedSlice(100, 200)
	defer view.Release()
	for _, action := range []func(){
		func() { view.OverCap(1) },
		func() { view.SharedSlice(-1, 5) },
		func() { view.SharedSlice(0, 101) },
		func() { view.SharedSlice(10, 9) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Error("out-of-range operation succeeded")
				}
			}()
			action()
		}()
	}
}
