package memo_test

import (
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/thinkonmay/global-proxy/api/pkg/memo"
)

func TestCache_BuildsOncePerKey(t *testing.T) {
	var builds atomic.Int64
	c := memo.New(0, func(k string) int {
		builds.Add(1)
		return len(k)
	})

	if got := c.Get("abc"); got != 3 {
		t.Fatalf("Get = %d, want 3", got)
	}
	c.Get("abc")
	c.Get("abc")
	if builds.Load() != 1 {
		t.Fatalf("builds = %d, want 1 (cached after first)", builds.Load())
	}
}

func TestCache_EvictsLeastRecentlyUsed(t *testing.T) {
	var builds atomic.Int64
	c := memo.New(2, func(k string) string {
		builds.Add(1)
		return k
	})

	c.Get("a")
	c.Get("b")
	c.Get("a")  // touch a => b is now least-recently-used
	c.Get("c")  // over capacity => evicts b
	if c.Len() != 2 {
		t.Fatalf("Len = %d, want 2", c.Len())
	}

	c.Get("a") // still cached, no rebuild
	c.Get("c") // still cached, no rebuild
	if builds.Load() != 3 {
		t.Fatalf("builds = %d, want 3 (a,b,c)", builds.Load())
	}
	c.Get("b") // was evicted => rebuilds
	if builds.Load() != 4 {
		t.Fatalf("builds = %d, want 4 (b rebuilt)", builds.Load())
	}
}

func TestCache_UnboundedNeverEvicts(t *testing.T) {
	c := memo.New(0, func(k int) int { return k })
	for i := range 1000 {
		c.Get(i)
	}
	if c.Len() != 1000 {
		t.Fatalf("Len = %d, want 1000 (unbounded)", c.Len())
	}
}

// Concurrent Get must be race-free and still build each key once. Run with -race.
func TestCache_ConcurrentGet(t *testing.T) {
	var builds atomic.Int64
	c := memo.New(0, func(string) int {
		builds.Add(1)
		return 1
	})

	const keys, goroutines = 50, 8
	var wg sync.WaitGroup
	for range goroutines {
		wg.Go(func() {
			for i := range keys {
				c.Get(strconv.Itoa(i))
			}
		})
	}
	wg.Wait()
	if builds.Load() != keys {
		t.Fatalf("builds = %d, want %d (one per key)", builds.Load(), keys)
	}
}
