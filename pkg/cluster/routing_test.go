package cluster

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/thinkonmay/global-proxy/api/pkg/routingagg"
)

func testRoutingStore(t *testing.T) *routingagg.Store {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mr.Close)
	store, err := routingagg.NewStore("redis://" + mr.Addr() + "/2")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestSyncRouting(t *testing.T) {
	store := testRoutingStore(t)
	out, err := SyncRouting(context.Background(), store, "haiphong.thinkmay.net", []RoutingEntry{
		{SessionID: "sess-1", NodeHost: "10.0.0.2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !out.Changed || out.Revision != 1 {
		t.Fatalf("result = %+v", out)
	}
}

func TestListRouting(t *testing.T) {
	store := testRoutingStore(t)
	ctx := context.Background()
	if _, err := SyncRouting(ctx, store, "peer.example", []RoutingEntry{
		{SessionID: "a", NodeHost: "10.1.1.1"},
	}); err != nil {
		t.Fatal(err)
	}
	clusters, err := ListRouting(ctx, store, "local.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(clusters) != 1 || clusters[0].Domain != "peer.example" {
		t.Fatalf("clusters = %+v", clusters)
	}
}

func TestRoutingEntriesFromJSON(t *testing.T) {
	body := []byte(`{"Sessions":[{"id":"s1","vm":{"Hostname":"worker1"}}]}`)
	entries := RoutingEntriesFromJSON(body, "fallback")
	if len(entries) != 1 || entries[0].SessionID != "s1" || entries[0].NodeHost != "worker1" {
		t.Fatalf("entries = %+v", entries)
	}
}
