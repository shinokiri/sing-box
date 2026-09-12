package cachefile

import (
	"fmt"
	"math/rand"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
)

func TestFakeIPMappingConsistency(t *testing.T) {
	for _, addressText := range []string{"198.18.0.2", "fc00::2"} {
		t.Run(addressText, func(t *testing.T) {
			cache := newFakeIPTestCache(t)
			var addresses []netip.Addr
			var domains []string
			address := netip.MustParseAddr(addressText)
			for index := range 8 {
				addresses = append(addresses, address)
				domains = append(domains, fmt.Sprintf("test-%d.example", index))
				address = address.Next()
			}
			owners := make(map[netip.Addr]string)
			random := rand.New(rand.NewSource(0))
			for operation := range 128 {
				address := addresses[random.Intn(len(addresses))]
				domain := domains[random.Intn(len(domains))]
				cache.FakeIPStoreAsync(address, domain, logger.NOP())
				owners[address] = domain
				if operation%7 == 0 {
					cache.Flush()
				}
				for _, domain := range domains {
					if got, found := cache.FakeIPLoadDomain(domain, address.Is6()); found && owners[got] != domain {
						t.Fatalf("operation %d: %s -> %v belongs to %s", operation, domain, got, owners[got])
					}
				}
				for address, owner := range owners {
					if got, found := cache.FakeIPLoad(address); !found || got != owner {
						t.Fatalf("operation %d: reverse lookup %v = %s, %v; want %s", operation, address, got, found, owner)
					}
				}
			}
			cache.Flush()
			for _, domain := range domains {
				if got, found := cache.FakeIPLoadDomain(domain, addresses[0].Is6()); found && owners[got] != domain {
					t.Fatalf("persisted mapping %s -> %v belongs to %s", domain, got, owners[got])
				}
			}
		})
	}
}

func TestFakeIPLookupsAcrossFlush(t *testing.T) {
	cache := newFakeIPTestCache(t)
	const entries = 32
	addresses := make([]netip.Addr, entries)
	oldDomains := make([]string, entries)
	newDomains := make([]string, entries)
	address := netip.MustParseAddr("198.18.0.2")
	for index := range entries {
		addresses[index] = address
		oldDomains[index] = fmt.Sprintf("old-%d.example", index)
		newDomains[index] = fmt.Sprintf("new-%d.example", index)
		cache.FakeIPStoreAsync(address, oldDomains[index], logger.NOP())
		address = address.Next()
	}
	cache.Flush()
	for index, address := range addresses {
		cache.FakeIPStoreAsync(address, newDomains[index], logger.NOP())
	}
	// All old assignments are invalid before any reader or flush starts.
	if got, found := cache.FakeIPLoadDomain(oldDomains[0], false); found {
		t.Errorf("old assignment is still visible before flush: %v", got)
	}
	start := make(chan struct{})
	var workers sync.WaitGroup
	for worker := range 3 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			for iteration := range 512 {
				index := (iteration + worker) % entries
				if got, found := cache.FakeIPLoadDomain(oldDomains[index], false); found {
					t.Errorf("stale assignment became visible across flush: %s -> %v", oldDomains[index], got)
					return
				}
				if got, found := cache.FakeIPLoadDomain(newDomains[index], false); !found || got != addresses[index] {
					t.Errorf("new assignment lost across flush: %s -> %v, %v", newDomains[index], got, found)
					return
				}
			}
		}()
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		<-start
		cache.Flush()
	}()
	close(start)
	finished := make(chan struct{})
	go func() {
		workers.Wait()
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("lookups and flush did not complete")
	}
}
