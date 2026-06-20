package metricsagg

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

func testCache(t *testing.T) (*Cache, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mr.Close)
	cache, err := NewCacheWithOptions(CacheOptions{
		RedisURL:           "redis://" + mr.Addr() + "/1",
		NodeTTLSeconds:     90,
		ScrapeCacheSeconds: 30,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cache.Close() })
	return cache, mr
}

func TestMergedExpositionScrapeCache(t *testing.T) {
	cache, mr := testCache(t)
	ctx := context.Background()

	if err := cache.SavePush(ctx, "worker-a", "node-exporter", []byte("cpu_usage 1\n")); err != nil {
		t.Fatal(err)
	}
	first, err := cache.MergedExposition(ctx)
	if err != nil {
		t.Fatal(err)
	}
	mr.FlushAll()
	second, err := cache.MergedExposition(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("expected scrape cache hit after redis flush")
	}
}

func TestMergedExpositionStaleNode(t *testing.T) {
	cache, _ := testCache(t)
	ctx := context.Background()

	if err := cache.client.SAdd(ctx, nodesIndexKey, "ghost-node").Err(); err != nil {
		t.Fatal(err)
	}
	body, err := cache.MergedExposition(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte(`thinkmay_node_up{node="ghost-node"} 0`)) {
		t.Fatalf("missing stale marker: %s", body)
	}
}

func TestListNodeInfo(t *testing.T) {
	cache, _ := testCache(t)
	ctx := context.Background()
	payload := []byte(`{"Hostname":"worker-a","Sessions":[]}`)
	if err := cache.SavePush(ctx, "worker-a", "info", payload); err != nil {
		t.Fatal(err)
	}
	nodes, err := cache.ListNodeInfo(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || string(nodes[0].Info) != string(payload) {
		t.Fatalf("nodes: %+v", nodes)
	}
}

func TestL1SurvivesRedisFlushAfterPush(t *testing.T) {
	cache, mr := testCache(t)
	ctx := context.Background()

	if err := cache.SavePush(ctx, "worker-b", "node-exporter", []byte("mem_usage 2\n")); err != nil {
		t.Fatal(err)
	}
	// Warm merged cache, then expire it so loadSnapshots runs again.
	if _, err := cache.MergedExposition(ctx); err != nil {
		t.Fatal(err)
	}
	cache.mu.Lock()
	cache.mergedAt = cache.mergedAt.Add(-31 * time.Second)
	cache.mu.Unlock()

	mr.FlushAll()
	body, err := cache.MergedExposition(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte("mem_usage 2")) {
		t.Fatalf("L1 miss after redis flush: %s", body)
	}
}
