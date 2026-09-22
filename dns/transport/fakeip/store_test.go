package fakeip_test

import (
	"context"
	"errors"
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

func TestStoreRestartsWithoutMetadata(t *testing.T) {
	cache := cachefile.New(context.Background(), logger.NOP(), option.CacheFileOptions{
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
	// Seed the observed disk state: an IPv4 mapping, no IPv6 bucket, and no
	// allocator metadata. No real device cache or network connection is used.
	oldAddress := netip.MustParseAddr("198.18.0.21")
	if err := cache.FakeIPStore(oldAddress, "linux.do"); err != nil {
		t.Fatal(err)
	}
	ctx := service.ContextWith[adapter.CacheFile](context.Background(), cache)
	store := fakeip.NewStore(ctx, logger.NOP(), netip.MustParsePrefix("198.18.0.0/15"), netip.Prefix{})
	if err := store.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	for index := range 19 {
		if _, err := store.Create(fmt.Sprintf("filler-%d.example", index), false); err != nil {
			t.Fatal(err)
		}
	}
	yuewenAddress, err := store.Create("ywaqstatic.yuewen.com", false)
	if err != nil {
		t.Fatal(err)
	}
	linuxAddress, err := store.Create("linux.do", false)
	if err != nil {
		t.Fatal(err)
	}
	linuxReverse, found := store.Lookup(linuxAddress)
	t.Logf("linux.do -> %v; ywaqstatic.yuewen.com -> %v; linux address reverse -> %q", linuxAddress, yuewenAddress, linuxReverse)
	if linuxAddress == yuewenAddress || !found || linuxReverse != "linux.do" {
		t.Fatalf("allocator restart returned an address belonging to another domain")
	}
	cache.Flush()
	if got, found := cache.FakeIPLoadDomain("linux.do", false); !found || got != linuxAddress {
		t.Errorf("linux.do mapping did not survive flush: %v, %v", got, found)
	}
}

type resetFailingCache struct {
	adapter.CacheFile
	err error
}

func (c *resetFailingCache) StoreFakeIP() bool                       { return true }
func (c *resetFailingCache) FakeIPMetadata() *adapter.FakeIPMetadata { return nil }
func (c *resetFailingCache) FakeIPReset() error                      { return c.err }

func TestStoreStartRejectsFailedReset(t *testing.T) {
	resetError := errors.New("storage reset failed")
	ctx := service.ContextWith[adapter.CacheFile](context.Background(), &resetFailingCache{err: resetError})
	store := fakeip.NewStore(ctx, logger.NOP(), netip.MustParsePrefix("198.18.0.0/15"), netip.Prefix{})
	if err := store.Start(); !errors.Is(err, resetError) {
		t.Fatalf("start ignored failed storage reset: got %v; want %v", err, resetError)
	}
}

func TestStoreRestartPreservesReservedAddresses(t *testing.T) {
	for _, isIPv6 := range []bool{false, true} {
		t.Run(fmt.Sprintf("ipv6=%v", isIPv6), func(t *testing.T) {
			options := option.CacheFileOptions{
				Path:        filepath.Join(t.TempDir(), "cache.db"),
				StoreFakeIP: true,
			}
			cache := cachefile.New(context.Background(), logger.NOP(), options)
			if err := cache.Start(adapter.StartStateInitialize); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := cache.Close(); err != nil {
					t.Error(err)
				}
			})
			newStore := func() *fakeip.Store {
				ctx := service.ContextWith[adapter.CacheFile](context.Background(), cache)
				store := fakeip.NewStore(ctx, logger.NOP(), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("fc00::/18"))
				if err := store.Start(); err != nil {
					t.Fatal(err)
				}
				return store
			}
			store := newStore()
			first, err := store.Create("before-restart.example", isIPv6)
			if err != nil {
				t.Fatal(err)
			}
			metadata := cache.FakeIPMetadata()
			if metadata == nil {
				t.Fatal("address allocation did not persist its reservation")
			}
			reserved := metadata.Inet4Current
			if isIPv6 {
				reserved = metadata.Inet6Current
			}
			if reserved.Compare(first) <= 0 {
				t.Fatalf("reservation does not extend past the allocated address: %v <= %v", reserved, first)
			}
			// Reopen the real database without Store.Close: the allocator never
			// replaces its reservation with a graceful-shutdown checkpoint.
			if err := cache.Close(); err != nil {
				t.Fatal(err)
			}
			cache = cachefile.New(context.Background(), logger.NOP(), options)
			if err := cache.Start(adapter.StartStateInitialize); err != nil {
				t.Fatal(err)
			}
			restarted := newStore()
			restored, err := restarted.Create("before-restart.example", isIPv6)
			if err != nil || restored != first {
				t.Fatalf("restart lost the persisted mapping: %v, %v", restored, err)
			}
			next, err := restarted.Create("after-restart.example", isIPv6)
			if err != nil || next != reserved.Next() {
				t.Fatalf("restart reused the reserved address block: %v, %v; want %v", next, err, reserved.Next())
			}
			if err := restarted.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
