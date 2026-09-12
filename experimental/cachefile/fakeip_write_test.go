package cachefile

import (
	"errors"
	"fmt"
	"net/netip"
	"testing"

	"github.com/sagernet/bbolt"
	"github.com/sagernet/sing/common/logger"
)

func TestPutFakeIPRollbackPreservesMappings(t *testing.T) {
	cache := newFakeIPTestCache(t)
	addresses := []netip.Addr{netip.MustParseAddr("198.18.0.21"), netip.MustParseAddr("fc00::21")}
	for _, address := range addresses {
		cache.FakeIPStoreAsync(address, "old.example", logger.NOP())
	}
	cache.Flush()
	abort := errors.New("abort fakeip migration")
	err := cache.DB.Update(func(tx *bbolt.Tx) error {
		for _, address := range addresses {
			if err := putFakeIP(tx, address.Next(), "old.example"); err != nil {
				return err
			}
			if err := putFakeIP(tx, address, "replacement.example"); err != nil {
				return err
			}
		}
		return abort
	})
	if !errors.Is(err, abort) {
		t.Fatal(err)
	}
	for _, address := range addresses {
		if got, found := cache.FakeIPLoadDomain("old.example", address.Is6()); !found || got != address {
			t.Fatalf("rollback changed forward mapping: %v %v", got, found)
		}
		if owner, found := cache.FakeIPLoad(address); !found || owner != "old.example" {
			t.Fatalf("rollback changed reverse mapping: %q %v", owner, found)
		}
		if got, found := cache.FakeIPLoadDomain("replacement.example", address.Is6()); found {
			t.Fatalf("rollback retained replacement domain: %v", got)
		}
		if owner, found := cache.FakeIPLoad(address.Next()); found {
			t.Fatalf("rollback retained new address: %q", owner)
		}
	}
}

// Measure mapping writes separately from transaction setup and filesystem sync.
// The flush benchmarks below include the actual commit and its default sync.
func BenchmarkFakeIPWriteTransaction(b *testing.B) {
	cache := newFakeIPTestCache(b)
	addresses, domains := fakeIPFlushInputs(256)
	tx, err := cache.DB.Begin(true)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		if err := tx.Rollback(); err != nil {
			b.Error(err)
		}
	})
	for i, address := range addresses {
		if err := putFakeIP(tx, address, domains[0][i]); err != nil {
			b.Fatal(err)
		}
	}
	index := 0
	b.ReportAllocs()
	for b.Loop() {
		entry := index & (len(addresses) - 1)
		generation := (index / len(addresses)) & 1
		if err := putFakeIP(tx, addresses[entry], domains[generation][entry]); err != nil {
			b.Fatal(err)
		}
		index++
	}
}

func fakeIPFlushInputs(count int) ([]netip.Addr, [2][]string) {
	addresses := make([]netip.Addr, count)
	domains := [2][]string{make([]string, count), make([]string, count)}
	v4 := netip.MustParseAddr("198.18.0.2")
	v6 := netip.MustParseAddr("fc00::2")
	for i := range addresses {
		if i%2 == 0 {
			addresses[i] = v4
			v4 = v4.Next()
		} else {
			addresses[i] = v6
			v6 = v6.Next()
		}
		domains[0][i] = fmt.Sprintf("first-%d.example", i)
		domains[1][i] = fmt.Sprintf("second-%d.example", i)
	}
	return addresses, domains
}

func BenchmarkFakeIPFlush(b *testing.B) {
	for _, count := range []int{1, 256, 4096} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			cache := newFakeIPTestCache(b)
			cache.bufferSize = 1 << 30
			addresses, domains := fakeIPFlushInputs(count)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				for j, address := range addresses {
					cache.FakeIPStoreAsync(address, domains[i&1][j], logger.NOP())
				}
				b.StartTimer()
				cache.Flush()
			}
			b.StopTimer()
			for j, address := range addresses {
				want := domains[(b.N-1)&1][j]
				if got, found := cache.FakeIPLoad(address); !found || got != want {
					b.Fatalf("flush lost %v: %q %v", address, got, found)
				}
			}
		})
	}
}

func BenchmarkFakeIPFlushFresh(b *testing.B) {
	for _, count := range []int{1, 256, 4096} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			cache := newFakeIPTestCache(b)
			cache.bufferSize = 1 << 30
			addresses, domains := fakeIPFlushInputs(count)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				if err := cache.FakeIPReset(); err != nil {
					b.Fatal(err)
				}
				for j, address := range addresses {
					cache.FakeIPStoreAsync(address, domains[0][j], logger.NOP())
				}
				b.StartTimer()
				cache.Flush()
			}
			b.StopTimer()
			for j, address := range addresses {
				if got, found := cache.FakeIPLoadDomain(domains[0][j], address.Is6()); !found || got != address {
					b.Fatal("fresh flush lost forward mapping")
				}
			}
		})
	}
}

func TestFakeIPFlushLargeBatchMoves(t *testing.T) {
	cache := newFakeIPTestCache(t)
	cache.bufferSize = 1 << 30
	addresses, domains := fakeIPMigrationInputs()
	for i, address := range addresses {
		cache.FakeIPStoreAsync(address, domains[i], logger.NOP())
	}
	cache.Flush()
	moved := make([]netip.Addr, len(addresses))
	for i, address := range addresses {
		moved[i] = address.Next()
		cache.FakeIPStoreAsync(moved[i], domains[i], logger.NOP())
		cache.FakeIPStoreAsync(address, "replacement-"+domains[i], logger.NOP())
	}
	cache.Flush()
	for i, address := range addresses {
		for domain, want := range map[string]netip.Addr{domains[i]: moved[i], "replacement-" + domains[i]: address} {
			if got, found := cache.FakeIPLoadDomain(domain, address.Is6()); !found || got != want {
				t.Fatalf("large batch %s = %v %v; want %v", domain, got, found, want)
			}
			if got, found := cache.FakeIPLoad(want); !found || got != domain {
				t.Fatalf("large batch reverse %v = %q %v; want %q", want, got, found, domain)
			}
		}
	}
}

func fakeIPMigrationInputs() ([]netip.Addr, []string) {
	addresses := make([]netip.Addr, 512)
	domains := make([]string, len(addresses))
	v4, v6 := netip.MustParseAddr("198.18.0.2"), netip.MustParseAddr("fc00::2")
	for i := range addresses {
		if i%2 == 0 {
			addresses[i] = v4
			v4 = v4.Next().Next()
		} else {
			addresses[i] = v6
			v6 = v6.Next().Next()
		}
		domains[i] = addresses[i].String() + ".example"
	}
	return addresses, domains
}
