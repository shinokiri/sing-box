package cachefile

import (
	"fmt"
	"net/netip"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/logger"
)

func TestFakeIPBufferedWritesDuringDatabaseWait(t *testing.T) {
	cache := newFakeIPTestCache(t)
	address := netip.MustParseAddr("198.18.0.2")
	if err := cache.FakeIPStore(address, "disk.example"); err != nil {
		t.Fatal(err)
	}
	// Hold database access while a persisted lookup starts. It must not
	// hold the shared pending lock and stop an unrelated buffered write.
	cache.dbAccess.Lock()
	locked := true
	defer func() {
		if locked {
			cache.dbAccess.Unlock()
		}
	}()
	reader := make(chan struct{})
	go func() {
		defer close(reader)
		if got, found := cache.FakeIPLoadDomain("disk.example", false); !found || got != address {
			t.Errorf("read after database resumes: %v, %v", got, found)
		}
	}()
	deadline := time.Now().Add(3 * time.Second)
	stack := make([]byte, 1<<20)
	for {
		n := runtime.Stack(stack, true)
		if strings.Contains(string(stack[:n]), "(*CacheFile).database") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("reader did not enter database access")
		}
		time.Sleep(time.Millisecond)
	}
	writer := make(chan struct{})
	go func() {
		cache.FakeIPStoreAsync(address.Next(), "pending.example", logger.NOP())
		close(writer)
	}()
	writeBeforeResume := false
	select {
	case <-writer:
		writeBeforeResume = true
	case <-time.After(time.Second):
	}
	cache.dbAccess.Unlock()
	locked = false
	for _, done := range []chan struct{}{reader, writer} {
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("operation did not finish after database access resumed")
		}
	}
	if !writeBeforeResume {
		t.Error("buffered write waited for unrelated database access")
	}
}

func BenchmarkFakeIPMixed(b *testing.B) {
	cache := newFakeIPTestCache(b)
	const entries = 8192
	domains := make([]string, entries)
	addresses := make([]netip.Addr, entries)
	address := netip.MustParseAddr("198.18.0.2")
	for i := range domains {
		domains[i] = fmt.Sprintf("read-%d.example", i)
		addresses[i] = address
		cache.FakeIPStoreAsync(address, domains[i], logger.NOP())
		address = address.Next()
	}
	cache.Flush()
	writes := make([]string, 64)
	writeAddresses := make([]netip.Addr, 64)
	address = netip.MustParseAddr("198.19.0.2")
	for i := range writes {
		writes[i] = fmt.Sprintf("write-%d.example", i)
		writeAddresses[i] = address
		address = address.Next()
	}
	var sequence atomic.Uint64
	var sampleAccess sync.Mutex
	var writeSamples, flushSamples []int64
	b.ReportAllocs()
	b.ResetTimer()
	// Four workers via -cpu=4. Each 64th operation queues an unrelated
	// buffered write; each 1024th operation also performs a real flush.
	b.RunParallel(func(pb *testing.PB) {
		localWrites := make([]int64, 0, 4096)
		localFlushes := make([]int64, 0, 256)
		for pb.Next() {
			op := sequence.Add(1)
			if op%64 != 0 {
				i := op & (entries - 1)
				if got, found := cache.FakeIPLoadDomain(domains[i], false); !found || got != addresses[i] {
					b.Errorf("stable read mapping changed: %v, %v", got, found)
				}
				continue
			}
			i := (op / 64) & 63
			start := time.Now()
			cache.FakeIPStoreAsync(writeAddresses[i], writes[i], logger.NOP())
			localWrites = append(localWrites, time.Since(start).Nanoseconds())
			if op%1024 == 0 {
				start = time.Now()
				cache.Flush()
				localFlushes = append(localFlushes, time.Since(start).Nanoseconds())
			}
		}
		sampleAccess.Lock()
		writeSamples = append(writeSamples, localWrites...)
		flushSamples = append(flushSamples, localFlushes...)
		sampleAccess.Unlock()
	})
	b.StopTimer()
	for name, samples := range map[string][]int64{"write": writeSamples, "flush": flushSamples} {
		slices.Sort(samples)
		if len(samples) == 0 {
			continue
		}
		b.ReportMetric(float64(samples[(len(samples)-1)*95/100]), name+"-p95-ns")
		b.ReportMetric(float64(samples[(len(samples)-1)*99/100]), name+"-p99-ns")
	}
}
