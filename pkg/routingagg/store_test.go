package routingagg

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
)

func testStore(t *testing.T) (*Store, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mr.Close)
	store, err := NewStore("redis://" + mr.Addr() + "/2")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, mr
}

func TestSyncNoChangeSkipsRevision(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()

	first, err := store.Sync(ctx, "Haiphong.Thinkmay.net", []Entry{
		{SessionID: "S1", NodeHost: "10.0.0.2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !first.Changed || first.Revision != 1 {
		t.Fatalf("first = %+v", first)
	}

	second, err := store.Sync(ctx, "haiphong.thinkmay.net", []Entry{
		{SessionID: "s1", NodeHost: "10.0.0.2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.Changed || second.Revision != 1 {
		t.Fatalf("second = %+v", second)
	}
}

func TestSyncChangeIncrementsRevision(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()

	if _, err := store.Sync(ctx, "peer.example", []Entry{
		{SessionID: "a", NodeHost: "10.1.1.1"},
	}); err != nil {
		t.Fatal(err)
	}
	out, err := store.Sync(ctx, "peer.example", []Entry{
		{SessionID: "a", NodeHost: "10.1.1.1"},
		{SessionID: "b", NodeHost: "10.1.1.2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !out.Changed || out.Revision != 2 {
		t.Fatalf("out = %+v", out)
	}
}

func TestListExcludesDomain(t *testing.T) {
	store, _ := testStore(t)
	ctx := context.Background()

	for _, d := range []string{"local.example", "peer.example"} {
		if _, err := store.Sync(ctx, d, []Entry{
			{SessionID: "s", NodeHost: "10.0.0.1"},
		}); err != nil {
			t.Fatal(err)
		}
	}

	clusters, err := store.List(ctx, "local.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(clusters) != 1 || clusters[0].Domain != "peer.example" {
		t.Fatalf("clusters = %+v", clusters)
	}
}
