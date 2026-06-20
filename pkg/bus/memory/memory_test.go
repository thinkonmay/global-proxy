package busmemory

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
)

func TestPublishSubscribeRoundTrip(t *testing.T) {
	m := New(nil)
	var count atomic.Int32
	m.Subscribe("orders", "g1", func(_ context.Context, payloads [][]byte) []error {
		count.Add(int32(len(payloads)))
		return nil
	}, bus.SubscribeOptions{BatchSize: 1})

	payload, _ := json.Marshal(map[string]int{"n": 1})
	if err := m.Publish(context.Background(), "orders", payload); err != nil {
		t.Fatal(err)
	}
	m.Wait()
	if count.Load() != 1 {
		t.Fatalf("count: %d", count.Load())
	}
}

func TestPublishAfterClose(t *testing.T) {
	m := New(nil)
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if err := m.Publish(context.Background(), "x", []byte("1")); err != bus.ErrClosed {
		t.Fatalf("expected ErrClosed, got %v", err)
	}
}
