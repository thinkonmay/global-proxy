package cachememory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/thinkonmay/global-proxy/api/pkg/cache"
	cachememory "github.com/thinkonmay/global-proxy/api/pkg/cache/memory"
)

func TestMemory_MissAndDelete(t *testing.T) {
	m := cachememory.New()
	t.Cleanup(func() { _ = m.Close() })
	ctx := context.Background()

	if _, err := m.Get(ctx, "absent"); !errors.Is(err, cache.ErrMiss) {
		t.Fatalf("Get absent = %v, want ErrMiss", err)
	}
	_ = m.Set(ctx, "k", []byte("v"), 0)
	_ = m.Delete(ctx, "k")
	if _, err := m.Get(ctx, "k"); !errors.Is(err, cache.ErrMiss) {
		t.Fatalf("Get after delete = %v, want ErrMiss", err)
	}
}

func TestMemory_TTLExpires(t *testing.T) {
	m := cachememory.New()
	t.Cleanup(func() { _ = m.Close() })
	ctx := context.Background()

	_ = m.Set(ctx, "k", []byte("v"), 20*time.Millisecond)
	if _, err := m.Get(ctx, "k"); err != nil {
		t.Fatalf("Get before expiry: %v", err)
	}
	time.Sleep(40 * time.Millisecond)
	if _, err := m.Get(ctx, "k"); !errors.Is(err, cache.ErrMiss) {
		t.Fatalf("Get after expiry = %v, want ErrMiss", err)
	}
}
