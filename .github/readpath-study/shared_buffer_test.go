package buf

import (
	"bytes"
	"sync"
	"testing"
)

func TestStudySharedLifetimeAndBounds(t *testing.T) {
	beforeBytes, beforeBlocks := StudySharedStorage()
	owner := NewSize(4096)
	owner.Write(bytes.Repeat([]byte{0x35}, 4096))
	one := owner.SharedSlice(100, 200)
	two := owner.SharedSlice(200, 300)
	child := one.SharedSlice(10, 20)
	one.Release()
	owner.Release()
	if !bytes.Equal(child.Bytes(), bytes.Repeat([]byte{0x35}, 10)) { t.Fatal("child invalidated") }
	two.Reset()
	if two.RawCap() != 100 || two.Cap() != 100 { t.Fatal("view escaped its range") }
	two.Write(bytes.Repeat([]byte{0x77}, 100))
	if child.Byte(0) != 0x35 { t.Fatal("sibling overwritten") }
	two.Release()
	child.IncRef()
	child.Release() // Preserve the existing pin/unpin contract.
	if child.Len() != 10 { t.Fatal("pinned view released") }
	child.DecRef()
	child.Release()
	child.Release() // A cleared handle remains safe to release again.
	afterBytes, afterBlocks := StudySharedStorage()
	if beforeBytes != afterBytes || beforeBlocks != afterBlocks { t.Fatal("storage leaked") }
}

func TestStudySharedConcurrentRelease(t *testing.T) {
	beforeBytes, beforeBlocks := StudySharedStorage()
	owner := NewSize(8192)
	owner.Extend(8192)
	views := make([]*Buffer, 128)
	for i := range views { views[i] = owner.SharedSlice(i*64, (i+1)*64) }
	var wg sync.WaitGroup
	for i, v := range views {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range v.Bytes() { v.SetByte(j, byte(i)) }
			v.Release()
		}()
	}
	owner.Release()
	wg.Wait()
	afterBytes, afterBlocks := StudySharedStorage()
	if beforeBytes != afterBytes || beforeBlocks != afterBlocks { t.Fatal("storage leaked") }
}

func TestStudySharedBufferOperations(t *testing.T) {
	for _, pooled := range []bool{false, true} {
		beforeBytes, beforeBlocks := StudySharedStorage()
		var owner *Buffer
		if pooled { owner = NewSize(4096); owner.Extend(4096) } else { owner = As(make([]byte, 4096)) }
		copy(owner.Bytes()[128:384], bytes.Repeat([]byte{0x51}, 256))
		view := owner.SharedSlice(128, 384)
		owner.Release()
		view.Advance(72)
		view.Truncate(64)
		clone := view.ToOwned()
		if clone.Start() != view.Start() || clone.FreeLen() != view.FreeLen() || !bytes.Equal(clone.Bytes(), view.Bytes()) { t.Fatal("ToOwned lost layout or bytes") }
		view.Reserve(16)
		view.OverCap(16)
		view.Reset()
		if view.Cap() != 256 || cap(view.Bytes()) != 256 { t.Fatal("reset escaped view") }
		view.Write(bytes.Repeat([]byte{0x62}, 256))
		if clone.Byte(0) != 0x51 { t.Fatal("ToOwned still shared payload") }
		view.Release()
		clone.Release()
		afterBytes, afterBlocks := StudySharedStorage()
		if beforeBytes != afterBytes || beforeBlocks != afterBlocks { t.Fatal("nonstandard lifetime leaked") }
	}
}

func TestStudySharedRangeRejectsEscape(t *testing.T) {
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
			defer func() { if recover() == nil { t.Error("out-of-range view operation succeeded") } }()
			action()
		}()
	}
}
