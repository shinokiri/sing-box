package cachefile

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/bbolt"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
)

func TestFakeIPKnownEmptyAfterReset(t *testing.T) {
	for _, text := range []string{"198.18.0.21", "fc00::21"} {
		t.Run(text, func(t *testing.T) {
			cache := newFakeIPTestCache(t)
			address := netip.MustParseAddr(text)
			if err := cache.FakeIPStore(address, "old.example"); err != nil {
				t.Fatal(err)
			}
			if err := cache.FakeIPReset(); err != nil {
				t.Fatal(err)
			}
			transactions := cache.DB.Stats().TxN
			if _, found := cache.FakeIPLoadDomain("old.example", address.Is6()); found {
				t.Fatal("reset retained a forward mapping")
			}
			if _, found := cache.FakeIPLoad(address); found {
				t.Fatal("reset retained a reverse mapping")
			}
			if count := cache.DB.Stats().TxN - transactions; count != 0 {
				t.Fatalf("known-empty lookups used %d read transactions", count)
			}
			cache.FakeIPStoreAsync(address, "new.example", logger.NOP())
			for _, layer := range []string{"pending", "disk"} {
				if layer == "disk" {
					cache.Flush()
				}
				if got, found := cache.FakeIPLoadDomain("new.example", address.Is6()); !found || got != address {
					t.Fatalf("%s forward mapping = %v %v", layer, got, found)
				}
				if got, found := cache.FakeIPLoad(address); !found || got != "new.example" {
					t.Fatalf("%s reverse mapping = %q %v", layer, got, found)
				}
			}
		})
	}
}

func TestFakeIPKnownEmptyAfterMetadataFlush(t *testing.T) {
	cache := newFakeIPTestCache(t)
	if err := cache.FakeIPReset(); err != nil {
		t.Fatal(err)
	}
	cache.FakeIPSaveMetadataAsync(&adapter.FakeIPMetadata{Inet4Range: netip.MustParsePrefix("198.18.0.0/15"), Inet4Current: netip.MustParseAddr("198.18.0.21")})
	cache.Flush()
	transactions := cache.DB.Stats().TxN
	if _, found := cache.FakeIPLoadDomain("absent.example", false); found {
		t.Fatal("metadata created an address mapping")
	}
	if count := cache.DB.Stats().TxN - transactions; count != 0 {
		t.Fatalf("metadata-only flush caused %d read transactions", count)
	}
}

func TestFakeIPReadsPersistedMappingAfterReopen(t *testing.T) {
	for _, text := range []string{"198.18.0.21", "fc00::21"} {
		t.Run(text, func(t *testing.T) {
			cache := newFakeIPTestCache(t)
			address := netip.MustParseAddr(text)
			if err := cache.FakeIPStore(address, "persisted.example"); err != nil {
				t.Fatal(err)
			}
			if err := cache.Close(); err != nil {
				t.Fatal(err)
			}
			reopened := New(context.Background(), logger.NOP(), option.CacheFileOptions{Path: cache.path, StoreFakeIP: true})
			if err := reopened.Start(adapter.StartStateInitialize); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := reopened.Close(); err != nil {
					t.Error(err)
				}
			})
			if got, found := reopened.FakeIPLoadDomain("persisted.example", address.Is6()); !found || got != address {
				t.Fatalf("reopen lost forward mapping: %v %v", got, found)
			}
			if got, found := reopened.FakeIPLoad(address); !found || got != "persisted.example" {
				t.Fatalf("reopen lost reverse mapping: %q %v", got, found)
			}
		})
	}
}

func TestFakeIPFailedResetPreservesPersistedMappings(t *testing.T) {
	for _, text := range []string{"198.18.0.21", "fc00::21"} {
		t.Run(text, func(t *testing.T) {
			cache := newFakeIPTestCache(t)
			address := netip.MustParseAddr(text)
			if err := cache.FakeIPReset(); err != nil {
				t.Fatal(err)
			}
			if err := cache.FakeIPStore(address, "persisted.example"); err != nil {
				t.Fatal(err)
			}
			// A read-only handle makes reset fail while persisted reads remain valid.
			if err := cache.DB.Close(); err != nil {
				t.Fatal(err)
			}
			readOnly, err := bbolt.Open(cache.path, 0o666, &bbolt.Options{ReadOnly: true, Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			cache.dbAccess.Lock()
			cache.DB = readOnly
			cache.dbAccess.Unlock()
			if err := cache.FakeIPReset(); err == nil {
				t.Fatal("read-only reset unexpectedly succeeded")
			}
			if got, found := cache.FakeIPLoadDomain("persisted.example", address.Is6()); !found || got != address {
				t.Fatalf("failed reset hid disk mapping: %v %v", got, found)
			}
			if owner, found := cache.FakeIPLoad(address); !found || owner != "persisted.example" {
				t.Fatalf("failed reset hid reverse mapping: %q %v", owner, found)
			}
		})
	}
}

func BenchmarkFakeIPAdmin(b *testing.B) {
	b.Run("reset_empty", func(b *testing.B) {
		cache := newFakeIPTestCache(b)
		b.ReportAllocs()
		for b.Loop() {
			if err := cache.FakeIPReset(); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("metadata_missing", func(b *testing.B) {
		cache := newFakeIPTestCache(b)
		b.ReportAllocs()
		for b.Loop() {
			if metadata := cache.FakeIPMetadata(); metadata != nil {
				b.Fatal("unexpected metadata")
			}
		}
	})
}

func BenchmarkFakeIPMiss(b *testing.B) {
	for _, phase := range []string{"empty_after_reset", "persisted_other_domain"} {
		b.Run(phase, func(b *testing.B) {
			cache := newFakeIPTestCache(b)
			if err := cache.FakeIPReset(); err != nil {
				b.Fatal(err)
			}
			if phase == "persisted_other_domain" {
				if err := cache.FakeIPStore(netip.MustParseAddr("198.18.0.21"), "present.example"); err != nil {
					b.Fatal(err)
				}
			}
			transactions := cache.DB.Stats().TxN
			b.ReportAllocs()
			for b.Loop() {
				if _, found := cache.FakeIPLoadDomain("absent.example", false); found {
					b.Fatal("unexpected hit")
				}
			}
			b.ReportMetric(float64(cache.DB.Stats().TxN-transactions)/float64(b.N), "read-tx/op")
		})
	}
}
