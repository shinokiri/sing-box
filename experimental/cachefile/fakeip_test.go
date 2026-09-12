package cachefile

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/sagernet/bbolt"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
)

func newFakeIPTestCache(t testing.TB) *CacheFile {
	t.Helper()
	cache := New(context.Background(), logger.NOP(), option.CacheFileOptions{
		Path:        filepath.Join(t.TempDir(), "cache.db"),
		StoreFakeIP: true,
	})
	if err := cache.Start(adapter.StartStateInitialize); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := cache.Close(); err != nil {
			t.Error(err)
		}
	})
	return cache
}

func TestBufferedFakeIPReassignment(t *testing.T) {
	for _, addressText := range []string{"198.18.0.21", "fc00::21"} {
		for _, olderLayer := range []string{"disk", "writing"} {
			t.Run(addressText+"/"+olderLayer, func(t *testing.T) {
				cache := newFakeIPTestCache(t)
				address := netip.MustParseAddr(addressText)
				const oldDomain = "linux.do"
				const newDomain = "ywaqstatic.yuewen.com"
				if olderLayer == "disk" {
					if err := cache.FakeIPStore(address, oldDomain); err != nil {
						t.Fatal(err)
					}
				} else {
					// Represent the immutable batch that an in-progress flush exposes.
					cache.pendingAccess.Lock()
					cache.writing = newPendingWrites()
					cache.writing.fakeIPDomain[address] = oldDomain
					if address.Is6() {
						cache.writing.fakeIPAddress6[oldDomain] = address
					} else {
						cache.writing.fakeIPAddress4[oldDomain] = address
					}
					cache.pendingAccess.Unlock()
				}
				cache.FakeIPStoreAsync(address, newDomain, logger.NOP())
				if got, found := cache.FakeIPLoad(address); !found || got != newDomain {
					t.Fatalf("reverse mapping = %q, %v; want %q", got, found, newDomain)
				}
				if got, found := cache.FakeIPLoadDomain(newDomain, address.Is6()); !found || got != address {
					t.Fatalf("new domain mapping = %v, %v; want %v", got, found, address)
				}
				if got, found := cache.FakeIPLoadDomain(oldDomain, address.Is6()); found {
					t.Errorf("stale forward mapping: %s -> %v, but reverse lookup belongs to %s", oldDomain, got, newDomain)
				}
			})
		}
	}
}

func TestFakeIPResetMissingAddressFamily(t *testing.T) {
	for _, addressText := range []string{"198.18.0.21", "fc00::21"} {
		t.Run(addressText, func(t *testing.T) {
			cache := newFakeIPTestCache(t)
			address := netip.MustParseAddr(addressText)
			if err := cache.FakeIPStore(address, "linux.do"); err != nil {
				t.Fatal(err)
			}
			if err := cache.FakeIPReset(); err != nil {
				t.Errorf("reset of a single-family cache failed: %v", err)
			}
			if domain, found := cache.FakeIPLoad(address); found {
				t.Errorf("reverse mapping survived reset: %v -> %s", address, domain)
			}
			if got, found := cache.FakeIPLoadDomain("linux.do", address.Is6()); found {
				t.Errorf("forward mapping survived reset: linux.do -> %v", got)
			}
		})
	}
}

func TestPutFakeIPPreservesMovedDomain(t *testing.T) {
	cache := newFakeIPTestCache(t)
	oldAddress := netip.MustParseAddr("198.18.0.21")
	newAddress := netip.MustParseAddr("198.18.0.22")
	err := cache.DB.Update(func(tx *bbolt.Tx) error {
		if err := putFakeIP(tx, oldAddress, "linux.do"); err != nil {
			return err
		}
		// A buffered flush may write a domain's new address before writing the
		// replacement owner of its old address, because it iterates a map.
		if err := putFakeIP(tx, newAddress, "linux.do"); err != nil {
			return err
		}
		return putFakeIP(tx, oldAddress, "ywaqstatic.yuewen.com")
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, found := cache.FakeIPLoadDomain("linux.do", false); !found || got != newAddress {
		t.Errorf("replacement deleted a newer forward mapping: got %v, %v; want %v", got, found, newAddress)
	}
}

func TestFakeIPResetEmptyCache(t *testing.T) {
	cache := newFakeIPTestCache(t)
	for range 2 {
		if err := cache.FakeIPReset(); err != nil {
			t.Errorf("reset must allow absent buckets: %v", err)
		}
	}
}
