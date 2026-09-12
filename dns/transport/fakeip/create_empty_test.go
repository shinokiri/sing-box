package fakeip_test

import (
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns/transport/fakeip"
	"github.com/sagernet/sing-box/experimental/cachefile"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"
)

func newPersistentFakeIPStore(t testing.TB) (*fakeip.Store, *cachefile.CacheFile) {
	t.Helper()
	cache := cachefile.New(context.Background(), logger.NOP(), option.CacheFileOptions{
		Path: filepath.Join(t.TempDir(), "cache.db"), StoreFakeIP: true,
	})
	if err := cache.Start(adapter.StartStateInitialize); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := cache.Close(); err != nil {
			t.Error(err)
		}
	})
	ctx := service.ContextWith[adapter.CacheFile](context.Background(), cache)
	store := fakeip.NewStore(ctx, logger.NOP(), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("fc00::/18"))
	if err := store.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	return store, cache
}

func TestFakeIPCreateBeforeFirstFlushAvoidsDatabaseReads(t *testing.T) {
	for _, family := range []string{"IPv4", "IPv6"} {
		t.Run(family, func(t *testing.T) {
			store, cache := newPersistentFakeIPStore(t)
			transactions := cache.DB.Stats().TxN
			isIPv6 := family == "IPv6"
			address, err := store.Create("new.example", isIPv6)
			if err != nil {
				t.Fatal(err)
			}
			if address.Is6() != isIPv6 {
				t.Fatalf("%s allocation returned %v", family, address)
			}
			if count := cache.DB.Stats().TxN - transactions; count != 0 {
				t.Fatalf("new allocation before first flush used %d read transactions", count)
			}
			if owner, found := store.Lookup(address); !found || owner != "new.example" {
				t.Fatalf("new address has wrong owner: %q %v", owner, found)
			}
		})
	}
}

// Use -benchtime=4096x to stay below the buffer threshold and address capacity.
func BenchmarkFakeIPCreateBeforeFirstFlush(b *testing.B) {
	for _, family := range []string{"IPv4", "IPv6"} {
		b.Run(family, func(b *testing.B) {
			if b.N > 8192 {
				b.Skip("Use -benchtime=4096x to measure allocation before the first flush")
			}
			store, cache := newPersistentFakeIPStore(b)
			domains := make([]string, b.N)
			for i := range domains {
				domains[i] = fmt.Sprintf("fresh-%d.example", i)
			}
			isIPv6 := family == "IPv6"
			transactions := cache.DB.Stats().TxN
			b.ReportAllocs()
			b.ResetTimer()
			for _, domain := range domains {
				if _, err := store.Create(domain, isIPv6); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(cache.DB.Stats().TxN-transactions)/float64(b.N), "read-tx/op")
		})
	}
}
