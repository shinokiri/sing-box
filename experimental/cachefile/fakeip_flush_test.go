package cachefile

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
)

func TestQueueFakeIPPreservesMovedDomain(t *testing.T) {
	for _, text := range []string{"198.18.0.21", "fc00::21"} {
		t.Run(text, func(t *testing.T) {
			cache := newFakeIPTestCache(t)
			oldAddress := netip.MustParseAddr(text)
			newAddress := oldAddress.Next()
			cache.FakeIPStoreAsync(oldAddress, "linux.do", logger.NOP())
			cache.FakeIPStoreAsync(newAddress, "linux.do", logger.NOP())
			cache.FakeIPStoreAsync(oldAddress, "ywaqstatic.yuewen.com", logger.NOP())
			for _, phase := range []string{"buffered", "flushed"} {
				if phase == "flushed" {
					cache.Flush()
				}
				if got, found := cache.FakeIPLoadDomain("linux.do", oldAddress.Is6()); !found || got != newAddress {
					t.Errorf("%s: newer domain mapping was lost: %v, %v", phase, got, found)
				}
			}
		})
	}
}

func TestBufferedFakeIPDuringFlush(t *testing.T) {
	for _, text := range []string{"198.18.0.21", "fc00::21"} {
		t.Run(text, func(t *testing.T) {
			cache := newFakeIPTestCache(t)
			oldAddress := netip.MustParseAddr(text)
			newAddress := oldAddress.Next()
			if err := cache.FakeIPStore(oldAddress, "linux.do"); err != nil {
				t.Fatal(err)
			}
			// Hold a real database writer so Flush exposes its immutable batch
			// while lookups and the next batch continue to run.
			blocker, err := cache.DB.Begin(true)
			if err != nil {
				t.Fatal(err)
			}
			cache.FakeIPStoreAsync(oldAddress, "ywaqstatic.yuewen.com", logger.NOP())
			flushed := make(chan struct{})
			go func() {
				cache.Flush()
				close(flushed)
			}()
			t.Cleanup(func() {
				_ = blocker.Rollback()
				select {
				case <-flushed:
				case <-time.After(5 * time.Second):
					t.Error("flush did not finish after releasing database writer")
				}
			})
			deadline := time.Now().Add(5 * time.Second)
			for {
				cache.pendingAccess.RLock()
				writing := cache.writing != nil
				cache.pendingAccess.RUnlock()
				if writing {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("flush did not expose the writing batch")
				}
				time.Sleep(time.Millisecond)
			}
			if got, found := cache.FakeIPLoadDomain("linux.do", oldAddress.Is6()); found {
				t.Errorf("disk mapping survived a newer writing batch: %v", got)
			}
			cache.FakeIPStoreAsync(newAddress, "linux.do", logger.NOP())
			checkMappings := func(phase string) {
				t.Helper()
				for domain, want := range map[string]netip.Addr{"linux.do": newAddress, "ywaqstatic.yuewen.com": oldAddress} {
					if got, found := cache.FakeIPLoadDomain(domain, oldAddress.Is6()); !found || got != want {
						t.Errorf("%s: %s resolved to %v, %v; want %v", phase, domain, got, found, want)
					}
					if got, found := cache.FakeIPLoad(want); !found || got != domain {
						t.Errorf("%s: reverse lookup returned %q, %v; want %s", phase, got, found, domain)
					}
				}
			}
			checkMappings("writing and pending")
			if err := blocker.Commit(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-flushed:
			case <-time.After(5 * time.Second):
				t.Fatal("flush did not complete")
			}
			checkMappings("disk and pending")
			cache.Flush()
			checkMappings("disk only")
		})
	}
}

func BenchmarkFakeIPLoadDomain(b *testing.B) {
	for _, count := range []int{256, 8192} {
		for _, layer := range []string{"pending", "writing", "disk"} {
			b.Run(fmt.Sprintf("%s/%d", layer, count), func(b *testing.B) {
				cache := newFakeIPTestCache(b)
				domains := make([]string, count)
				addresses := make([]netip.Addr, count)
				address := netip.MustParseAddr("198.18.0.2")
				for index := range domains {
					domains[index] = fmt.Sprintf("host-%d.example", index)
					addresses[index] = address
					cache.FakeIPStoreAsync(address, domains[index], logger.NOP())
					address = address.Next()
				}
				switch layer {
				case "writing":
					cache.pendingAccess.Lock()
					cache.writing = cache.pending
					cache.pending = newPendingWrites()
					cache.pendingAccess.Unlock()
				case "disk":
					cache.Flush()
				}
				transactions := cache.DB.Stats().TxN
				b.ReportAllocs()
				index := 0
				for b.Loop() {
					entry := index & (count - 1)
					if got, found := cache.FakeIPLoadDomain(domains[entry], false); !found || got != addresses[entry] {
						b.Fatalf("lookup %q = %v, %v; want %v", domains[entry], got, found, addresses[entry])
					}
					index++
				}
				b.ReportMetric(float64(cache.DB.Stats().TxN-transactions)/float64(b.N), "read-tx/op")
			})
		}
	}
}
