package cachefile

import (
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/logger"
)

func TestFakeIPResetPreservesOtherPendingEntries(t *testing.T) {
	for _, addressText := range []string{"198.18.0.21", "fc00::21"} {
		t.Run(addressText, func(t *testing.T) {
			cache := newFakeIPTestCache(t)
			cache.rdrcTimeout = time.Hour
			expiry := time.Now().Add(time.Hour).Truncate(time.Second)
			cache.SaveDNSCacheAsync("dns", "answer.example.", 1, []byte("cached-answer"), expiry, logger.NOP())
			cache.SaveRDRCAsync("dns", "blocked.example.", 28, logger.NOP())
			count, size := cache.pending.count, cache.pending.size
			address := netip.MustParseAddr(addressText)
			cache.FakeIPStoreAsync(address, "fake.example", logger.NOP())
			cache.FakeIPSaveMetadataAsync(&adapter.FakeIPMetadata{})
			if err := cache.FakeIPReset(); err != nil {
				t.Fatal(err)
			}
			if cache.pending.count != count || cache.pending.size != size {
				t.Errorf("reset changed unrelated pending accounting: count=%d size=%d; want %d %d", cache.pending.count, cache.pending.size, count, size)
			}
			if cache.pending.fakeIPMetadata != nil {
				t.Error("reset retained FakeIP metadata")
			}
			for _, layer := range []string{"pending", "disk"} {
				if layer == "disk" {
					cache.Flush()
				}
				raw, gotExpiry, found := cache.LoadDNSCache("dns", "answer.example.", 1)
				if !found || string(raw) != "cached-answer" || !gotExpiry.Equal(expiry) {
					t.Errorf("%s DNS cache changed across FakeIP reset: %q, %v, %v", layer, raw, gotExpiry, found)
				}
				if !cache.LoadRDRC("dns", "blocked.example.", 28) {
					t.Errorf("%s RDRC entry lost across FakeIP reset", layer)
				}
				if owner, found := cache.FakeIPLoad(address); found {
					t.Errorf("%s FakeIP entry survived reset: %q", layer, owner)
				}
			}
		})
	}
}

func TestFakeIPFailedResetPreservesPending(t *testing.T) {
	for _, addressText := range []string{"198.18.0.21", "fc00::21"} {
		t.Run(addressText, func(t *testing.T) {
			cache := newFakeIPTestCache(t)
			address := netip.MustParseAddr(addressText)
			cache.FakeIPStoreAsync(address, "keep.example", logger.NOP())
			metadata := &adapter.FakeIPMetadata{}
			cache.FakeIPSaveMetadataAsync(metadata)
			count, size := cache.pending.count, cache.pending.size
			if err := cache.DB.Close(); err != nil {
				t.Fatal(err)
			}
			if err := cache.FakeIPReset(); err == nil {
				t.Fatal("reset of a closed database unexpectedly succeeded")
			}
			if owner, found := cache.FakeIPLoad(address); !found || owner != "keep.example" {
				t.Errorf("failed reset discarded pending mapping: %q, %v", owner, found)
			}
			if got, found := cache.FakeIPLoadDomain("keep.example", address.Is6()); !found || got != address {
				t.Errorf("failed reset discarded pending forward mapping: %v, %v", got, found)
			}
			if cache.pending.fakeIPMetadata != metadata || cache.pending.count != count || cache.pending.size != size {
				t.Error("failed reset changed pending metadata or accounting")
			}
		})
	}
}
