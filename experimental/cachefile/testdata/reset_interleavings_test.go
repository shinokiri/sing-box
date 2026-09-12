// Scheduling hooks are installed only by .github/check_fakeip_interleavings.py.
// fakeip.go is always compiled from the current checkout.
package cachefile

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
)

type resetLookupResult struct {
	address netip.Addr
	found   bool
}

func resetPause(t *testing.T) (func(), <-chan struct{}, func()) {
	t.Helper()
	entered := make(chan struct{})
	resume := make(chan struct{})
	var pauseOnce, resumeOnce sync.Once
	release := func() { resumeOnce.Do(func() { close(resume) }) }
	t.Cleanup(release)
	return func() { pauseOnce.Do(func() { close(entered); <-resume }) }, entered, release
}

func resetWaitPause(t *testing.T, entered <-chan struct{}) {
	t.Helper()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("lookup did not reach the database pause")
	}
}

func resetLookup(cache *CacheFile, domain string, isIPv6 bool) <-chan resetLookupResult {
	result := make(chan resetLookupResult, 1)
	go func() {
		address, found := cache.FakeIPLoadDomain(domain, isIPv6)
		result <- resetLookupResult{address, found}
	}()
	return result
}

func resetResult(t *testing.T, result <-chan resetLookupResult) resetLookupResult {
	t.Helper()
	select {
	case value := <-result:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("lookup did not complete")
		return resetLookupResult{}
	}
}

func TestFakeIPInterleavingBufferedWrites(t *testing.T) {
	for _, addressText := range []string{"198.18.0.21", "fc00::21"} {
		t.Run(addressText, func(t *testing.T) {
			cache := newFakeIPTestCache(t)
			address := netip.MustParseAddr(addressText)
			if err := cache.FakeIPStore(address, "old.example"); err != nil {
				t.Fatal(err)
			}
			pause, entered, release := resetPause(t)
			cache.testBeforeView = pause
			result := resetLookup(cache, "old.example", address.Is6())
			resetWaitPause(t, entered)
			written := make(chan struct{})
			go func() {
				cache.FakeIPStoreAsync(address.Next(), "other.example", logger.NOP())
				close(written)
			}()
			select {
			case <-written:
				t.Log("buffered write completed while the database read was paused")
			case <-time.After(time.Second):
				t.Error("buffered write waited for the paused database read")
			}
			release()
			got := resetResult(t, result)
			if !got.found || got.address != address {
				t.Errorf("unrelated write changed the lookup: %+v", got)
			}
			select {
			case <-written:
			case <-time.After(5 * time.Second):
				t.Fatal("buffered writer did not finish")
			}
		})
	}
}

func TestFakeIPInterleavingRetiredOverride(t *testing.T) {
	for _, addressText := range []string{"198.18.0.21", "fc00::21"} {
		t.Run(addressText, func(t *testing.T) {
			cache := newFakeIPTestCache(t)
			address := netip.MustParseAddr(addressText)
			if err := cache.FakeIPStore(address, "old.example"); err != nil {
				t.Fatal(err)
			}
			cache.FakeIPStoreAsync(address, "new.example", logger.NOP())
			pause, entered, release := resetPause(t)
			cache.testAfterView = pause
			transactions := cache.DB.Stats().TxN
			result := resetLookup(cache, "old.example", address.Is6())
			resetWaitPause(t, entered)
			cache.Flush()
			release()
			if got := resetResult(t, result); got.found {
				t.Errorf("returned a retired override's stale forward mapping: %+v", got)
			}
			t.Logf("read transactions with completed-flush fallback: %d", cache.DB.Stats().TxN-transactions)
		})
	}
}

func TestFakeIPInterleavingPendingOverride(t *testing.T) {
	for _, addressText := range []string{"198.18.0.21", "fc00::21"} {
		t.Run(addressText, func(t *testing.T) {
			cache := newFakeIPTestCache(t)
			address := netip.MustParseAddr(addressText)
			if err := cache.FakeIPStore(address, "old.example"); err != nil {
				t.Fatal(err)
			}
			pause, entered, release := resetPause(t)
			cache.testAfterView = pause
			result := resetLookup(cache, "old.example", address.Is6())
			resetWaitPause(t, entered)
			cache.FakeIPStoreAsync(address, "new.example", logger.NOP())
			release()
			if got := resetResult(t, result); got.found {
				t.Errorf("returned an address overridden in the same pending batch: %+v", got)
			}
		})
	}
}

func TestFakeIPInterleavingStableRead(t *testing.T) {
	for _, addressText := range []string{"198.18.0.21", "fc00::21"} {
		t.Run(addressText, func(t *testing.T) {
			cache := newFakeIPTestCache(t)
			address := netip.MustParseAddr(addressText)
			if err := cache.FakeIPStore(address, "old.example"); err != nil {
				t.Fatal(err)
			}
			transactions := cache.DB.Stats().TxN
			if got, found := cache.FakeIPLoadDomain("old.example", address.Is6()); !found || got != address {
				t.Fatalf("stable lookup = %v, %v", got, found)
			}
			if count := cache.DB.Stats().TxN - transactions; count != 1 {
				t.Errorf("stable lookup used %d read transactions; want 1", count)
			}
		})
	}
}

func TestFakeIPInterleavingResetAfterSnapshot(t *testing.T) {
	for _, addressText := range []string{"198.18.0.21", "fc00::21"} {
		t.Run(addressText, func(t *testing.T) {
			cache := newFakeIPTestCache(t)
			address := netip.MustParseAddr(addressText)
			if err := cache.FakeIPStore(address, "old.example"); err != nil {
				t.Fatal(err)
			}
			// old.example is already invalid before the lookup starts.
			cache.FakeIPStoreAsync(address, "new.example", logger.NOP())
			pause, entered, release := resetPause(t)
			cache.testAfterView = pause
			result := resetLookup(cache, "old.example", address.Is6())
			resetWaitPause(t, entered)
			if err := cache.FakeIPReset(); err != nil {
				t.Fatal(err)
			}
			release()
			got := resetResult(t, result)
			if got.found {
				owner, present := cache.FakeIPLoad(got.address)
				t.Errorf("lookup returned a mapping invalid before the query and absent after reset: address=%v owner=%q present=%v", got.address, owner, present)
			}
		})
	}
}

func TestFakeIPInterleavingResetBeforeDatabase(t *testing.T) {
	for _, addressText := range []string{"198.18.0.21", "fc00::21"} {
		t.Run(addressText, func(t *testing.T) {
			cache := newFakeIPTestCache(t)
			address := netip.MustParseAddr(addressText)
			if err := cache.FakeIPStore(address, "old.example"); err != nil {
				t.Fatal(err)
			}
			cache.FakeIPStoreAsync(address, "new.example", logger.NOP())
			pause, entered, release := resetPause(t)
			cache.testBeforeBatch = pause
			reset := make(chan error, 1)
			go func() { reset <- cache.FakeIPReset() }()
			resetWaitPause(t, entered)
			result := resetLookup(cache, "old.example", address.Is6())
			consumed := false
			select {
			case got := <-result:
				consumed = true
				if got.found {
					t.Errorf("reset exposed a previously overridden disk mapping: %+v", got)
				}
			case <-time.After(200 * time.Millisecond):
			}
			release()
			select {
			case err := <-reset:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("reset did not finish")
			}
			if !consumed {
				if got := resetResult(t, result); got.found {
					t.Errorf("lookup returned a cleared mapping after reset: %+v", got)
				}
			}
		})
	}
}
