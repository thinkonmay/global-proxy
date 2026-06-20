package usage

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	busmemory "github.com/thinkonmay/global-proxy/api/pkg/bus/memory"
	"github.com/thinkonmay/global-proxy/api/pkg/metricsagg"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/shared/model"

	"github.com/alicebob/miniredis/v2"
)

func TestCollectorTickShadowPublishesAnalytics(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mr.Close)

	cache, err := metricsagg.NewCacheWithOptions(metricsagg.CacheOptions{
		RedisURL:       "redis://" + mr.Addr() + "/1",
		NodeTTLSeconds: 90,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cache.Close() })

	dedup, err := NewDedup("redis://" + mr.Addr() + "/1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dedup.Close() })

	var rpcMu sync.Mutex
	rpcCalls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/user_v2":
			_ = json.NewEncoder(w).Encode([]map[string]any{{
				"email":      "user@example.com",
				"volume_id":  "22222222-2222-2222-2222-222222222222",
				"cluster_id": float64(1),
			}})
		case r.URL.Path == "/clusters":
			_ = json.NewEncoder(w).Encode([]map[string]any{{
				"id": float64(1), "domain": "saigon2.thinkmay.net",
			}})
		case r.URL.Path == "/nodes":
			_ = json.NewEncoder(w).Encode([]map[string]any{{
				"name": "gpu-worker-01", "cluster_id": float64(1), "active": true,
			}})
		case r.URL.Path == "/rpc/increment_subscription_usage":
			rpcMu.Lock()
			rpcCalls++
			rpcMu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	pr := postgrest.New(postgrest.Config{URL: srv.URL, ServiceKey: "svc"})
	eventBus := busmemory.New(nil)
	var published []model.UsageMsg
	var pubMu sync.Mutex
	bus.Subscribe(eventBus, model.TopicUsage, "test", func(ctx context.Context, msg model.UsageMsg) error {
		pubMu.Lock()
		published = append(published, msg)
		pubMu.Unlock()
		return nil
	})

	collector := NewCollector(cache, NewCatalog(pr, time.Minute), dedup, pr, eventBus, nil, Options{
		ShadowMode:   true,
		TickInterval: 5 * time.Minute,
		SessionMins:  5,
	})

	if err := cache.SavePush(context.Background(), "gpu-worker-01", "info", []byte(sampleInfo)); err != nil {
		t.Fatal(err)
	}

	collector.tick(context.Background())
	eventBus.Wait()

	rpcMu.Lock()
	calls := rpcCalls
	rpcMu.Unlock()
	if calls != 0 {
		t.Fatalf("shadow mode rpc calls = %d", calls)
	}

	pubMu.Lock()
	n := len(published)
	pubMu.Unlock()
	if n < 2 {
		t.Fatalf("expected session+volume analytics events, got %d", n)
	}
}
