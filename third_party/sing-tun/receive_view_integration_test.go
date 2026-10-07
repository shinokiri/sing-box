//go:build shared_receive_study

package tun

import (
	"bytes"
	"testing"

	"github.com/sagernet/sing/common/buf"
)

func TestSharedReceiveTransmitStore(t *testing.T) {
	beforeBytes, beforeBlocks := buf.StudySharedStorage()
	const headerRoom, payloadSize, count = 72, 8192, 4
	owner := buf.NewSize((headerRoom+payloadSize)*count)
	owner.Extend((headerRoom+payloadSize)*count)
	var store goTransmitStore
	var want []byte
	for i := range count {
		start := i*(headerRoom+payloadSize)
		body := owner.SharedSlice(start, start+headerRoom+payloadSize)
		body.Advance(headerRoom)
		payload := bytes.Repeat([]byte{byte(i+1)}, payloadSize)
		copy(body.Bytes(), payload)
		want = append(want, payload...)
		if !store.adopt(uint64(i*payloadSize), body) { body.Release(); t.Fatal("store refused a record") }
	}
	owner.Release() // The Snell receiver can close before TCP acknowledges data.
	defer store.releaseAll()
	for i := range count {
		body, payload, found := store.leadingRun(uint64(i*payloadSize), payloadSize)
		if !found || body.Start() < headerRoom { t.Fatal("lost leading record or header room") }
		// The contiguous TCP transmit path writes its IP/TCP headers here.
		clear(body.ExtendHeader(headerRoom))
		body.Advance(headerRoom)
		if !bytes.Equal(payload, want[i*payloadSize:(i+1)*payloadSize]) { t.Fatal("header write changed payload") }
	}
	if got := bytes.Join(store.appendRuns(nil, 0, len(want)), nil); !bytes.Equal(got, want) { t.Fatal("scatter transmit changed records") }
	store.releaseBelow(2*payloadSize)
	if got := bytes.Join(store.appendRuns(nil, 2*payloadSize, 2*payloadSize), nil); !bytes.Equal(got, want[2*payloadSize:]) { t.Fatal("partial acknowledgement invalidated later records") }
	store.releaseAll()
	afterBytes, afterBlocks := buf.StudySharedStorage()
	if beforeBytes != afterBytes || beforeBlocks != afterBlocks { t.Fatal("transmit close leaked shared storage") }
}
