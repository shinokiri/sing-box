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
