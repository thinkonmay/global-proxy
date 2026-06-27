package volume

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	busmemory "github.com/thinkonmay/global-proxy/api/pkg/bus/memory"
	"github.com/thinkonmay/global-proxy/api/pkg/idempotency"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

func jobInsert(w http.ResponseWriter, r *http.Request, id int64) bool {
	if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/job") {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode([]map[string]any{{"id": id}})
		return true
	}
	return false
}

func provisionAndClusterMocks(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case "/rpc/provision_volume_v1":
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("null"))
		return true
	case "/clusters":
		if strings.Contains(r.URL.RawQuery, "id=eq.") {
			_ = json.NewEncoder(w).Encode([]map[string]any{{"id": 3, "domain": "test.thinkmay.net"}})
			return true
		}
	}
	return false
}

func rawArgs(t *testing.T, m map[string]any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newTestHandler(t *testing.T, extra func(w http.ResponseWriter, r *http.Request) bool) (*Handler, *sync.Mutex, map[string]any) {
	t.Helper()
	var mu sync.Mutex
	jobPatch := map[string]any{}
	prSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if extra != nil && extra(w, r) {
			return
		}
		if provisionAndClusterMocks(w, r) {
			return
		}
		switch {
		case jobInsert(w, r, 99):
			return
		case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/job"):
			_ = json.NewDecoder(r.Body).Decode(&jobPatch)
			mu.Lock()
			w.WriteHeader(http.StatusNoContent)
			mu.Unlock()
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(prSrv.Close)
	pr := postgrest.New(postgrest.Config{URL: prSrv.URL, ServiceKey: "svc"})
	return New(idempotency.New(idempotency.NewMemStore()), pr, nil), &mu, jobPatch
}

func TestVolumeHandlerCreateVolume(t *testing.T) {
	vh, mu, jobPatch := newTestHandler(t, nil)

	err := vh.handle(context.Background(), model.VolumeJobMsg{
		RequestID: "req-create",
		Command:   "create volume v7",
		ClusterID: 3,
		Arguments: rawArgs(t, map[string]any{"email": "u@example.com", "volume_id": "local-vol"}),
	})
	if err != nil {
		t.Fatalf("handle: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if jobPatch["success"] != true {
		t.Fatalf("job patch: %v", jobPatch)
	}
}

func TestVolumeHandlerUpdateVolume(t *testing.T) {
	var provisionCfg map[string]any
	vh, mu, jobPatch := newTestHandler(t, func(w http.ResponseWriter, r *http.Request) bool {
		switch r.URL.Path {
		case "/rpc/lookup_volume_configuration_v1":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"email":    "u@example.com",
				"template": "win11",
				"disk":     map[string]any{"size": 50},
				"plan":     "pro",
			})
			return true
		case "/rpc/provision_volume_v1":
			_ = json.NewDecoder(r.Body).Decode(&provisionCfg)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("null"))
			return true
		default:
			return false
		}
	})

	err := vh.handle(context.Background(), model.VolumeJobMsg{
		RequestID: "req-update",
		Command:   "update volume v7",
		ClusterID: 3,
		Arguments: rawArgs(t, map[string]any{"email": "u@example.com", "volume_id": "vol-1", "tier": "premium"}),
	})
	if err != nil {
		t.Fatalf("handle: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if jobPatch["success"] != true {
		t.Fatalf("job patch: %v", jobPatch)
	}
	cfg, ok := provisionCfg["configuration"].(map[string]any)
	if !ok {
		t.Fatalf("provision configuration: %v", provisionCfg)
	}
	if cfg["tier"] != "premium" || cfg["template"] != "win11" {
		t.Fatalf("merged configuration: %v", cfg)
	}
}

func TestVolumeHandlerDeleteVolume(t *testing.T) {
	var deprovisionCalled bool
	vh, mu, jobPatch := newTestHandler(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/rpc/deprovision_volume_v1" {
			deprovisionCalled = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("null"))
			return true
		}
		return false
	})

	err := vh.handle(context.Background(), model.VolumeJobMsg{
		RequestID: "req-delete",
		Command:   "delete volume v5",
		ClusterID: 3,
		Arguments: rawArgs(t, map[string]any{"email": "u@example.com", "volume_id": "vol-1"}),
	})
	if err != nil {
		t.Fatalf("handle: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if !deprovisionCalled {
		t.Fatal("deprovision RPC was not called")
	}
	if jobPatch["success"] != true {
		t.Fatalf("job patch: %v", jobPatch)
	}
}

func TestVolumeHandlerGrantJob(t *testing.T) {
	var mu sync.Mutex
	var jobPatch map[string]any
	var grantCalled bool

	prSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/clusters":
			_ = json.NewEncoder(w).Encode([]map[string]any{{
				"id":     3,
				"domain": "saigon2.thinkmay.net",
			}})
		case r.URL.Path == "/rpc/grant_app_access_v1":
			mu.Lock()
			grantCalled = true
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"granted": true})
		case jobInsert(w, r, 102):
			return
		case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/job"):
			mu.Lock()
			_ = json.NewDecoder(r.Body).Decode(&jobPatch)
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer prSrv.Close()

	pr := postgrest.New(postgrest.Config{URL: prSrv.URL, ServiceKey: "svc"})
	vh := New(idempotency.New(idempotency.NewMemStore()), pr, nil)

	err := vh.handle(context.Background(), model.VolumeJobMsg{
		RequestID: "req-grant",
		Command:   "grant app_access",
		ClusterID: 3,
		Arguments: rawArgs(t, map[string]any{"email": "u@example.com", "app_id": "steam-123"}),
	})
	if err != nil {
		t.Fatalf("handle: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if !grantCalled {
		t.Fatal("grant RPC was not called")
	}
	if jobPatch == nil || jobPatch["success"] != true {
		t.Fatalf("job patch: %v", jobPatch)
	}
}

func TestVolumeHandlerResetAppAccessJob(t *testing.T) {
	var mu sync.Mutex
	var jobPatch map[string]any
	var resetCalled bool

	prSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/clusters":
			_ = json.NewEncoder(w).Encode([]map[string]any{{
				"id":     3,
				"domain": "saigon2.thinkmay.net",
			}})
		case r.URL.Path == "/rpc/reset_user_app_access_usage_v1":
			mu.Lock()
			resetCalled = true
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(null)
		case jobInsert(w, r, 103):
			return
		case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/job"):
			mu.Lock()
			_ = json.NewDecoder(r.Body).Decode(&jobPatch)
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer prSrv.Close()

	pr := postgrest.New(postgrest.Config{URL: prSrv.URL, ServiceKey: "svc"})
	vh := New(idempotency.New(idempotency.NewMemStore()), pr, nil)

	err := vh.handle(context.Background(), model.VolumeJobMsg{
		RequestID: "req-reset",
		Command:   "reset app_access",
		ClusterID: 3,
		Arguments: rawArgs(t, map[string]any{"email": "u@example.com"}),
	})
	if err != nil {
		t.Fatalf("handle: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if !resetCalled {
		t.Fatal("reset RPC was not called")
	}
	if jobPatch == nil || jobPatch["success"] != true {
		t.Fatalf("job patch: %v", jobPatch)
	}
}

var null = json.RawMessage("null")

func TestVolumeHandlerSkipsUnknownCommand(t *testing.T) {
	var mu sync.Mutex
	var jobPatch map[string]any
	prSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if jobInsert(w, r, 55) {
			return
		}
		if r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/job") {
			_ = json.NewDecoder(r.Body).Decode(&jobPatch)
			mu.Lock()
			w.WriteHeader(http.StatusNoContent)
			mu.Unlock()
			return
		}
		http.NotFound(w, r)
	}))
	defer prSrv.Close()

	pr := postgrest.New(postgrest.Config{URL: prSrv.URL, ServiceKey: "svc"})
	vh := New(idempotency.New(idempotency.NewMemStore()), pr, nil)
	err := vh.handle(context.Background(), model.VolumeJobMsg{RequestID: "req-unknown", Command: "unknown"})
	if err != nil {
		t.Fatalf("expected nil for unknown command, got %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if jobPatch == nil || jobPatch["success"] != false {
		t.Fatalf("job patch: %v", jobPatch)
	}
}

func TestInitSubscribesVolumeTopic(t *testing.T) {
	bus := busmemory.New(nil)
	pr := postgrest.New(postgrest.Config{URL: "http://127.0.0.1:1"})
	h := New(idempotency.New(idempotency.NewMemStore()), pr, nil)
	h.Init(bus)

	err := bus.Publish(context.Background(), model.TopicVolumeJob.Name, []byte(`{"command":"unknown","request_id":"req-init"}`))
	if err != nil {
		t.Fatal(err)
	}
	bus.Wait()
}

func TestVolumeHandlerSkipsDuplicateDelivery(t *testing.T) {
	var jobInserts int
	prSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/job") {
			jobInserts++
			jobInsert(w, r, 200)
			return
		}
		if r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/job") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, r)
	}))
	defer prSrv.Close()

	pr := postgrest.New(postgrest.Config{URL: prSrv.URL, ServiceKey: "svc"})
	store := idempotency.NewMemStore()
	vh := New(idempotency.New(store), pr, nil)

	msg := model.VolumeJobMsg{RequestID: "req-dup", Command: "unknown"}
	if err := vh.handle(context.Background(), msg); err != nil {
		t.Fatalf("first handle: %v", err)
	}
	if err := vh.handle(context.Background(), msg); err != nil {
		t.Fatalf("second handle: %v", err)
	}
	if jobInserts != 1 {
		t.Fatalf("job inserts = %d, want 1 (idempotency skip)", jobInserts)
	}
}

func TestVolumeHandlerRecoversExistingJobOnRetry(t *testing.T) {
	var mu sync.Mutex
	var provisionCalls int
	var jobPosts int
	var jobPatch map[string]any

	prSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/rpc/provision_volume_v1" {
			mu.Lock()
			provisionCalls++
			call := provisionCalls
			mu.Unlock()
			if call == 1 {
				http.Error(w, "busy", http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("null"))
			return
		}
		if provisionAndClusterMocks(w, r) {
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/job":
			jobPosts++
			if jobPosts == 1 {
				jobInsert(w, r, 88)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"code":"23505"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/job":
			if strings.Contains(r.URL.RawQuery, "request_id=eq.req-retry") {
				_ = json.NewEncoder(w).Encode([]map[string]any{{"id": int64(88)}})
				return
			}
			http.NotFound(w, r)
		case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/job"):
			_ = json.NewDecoder(r.Body).Decode(&jobPatch)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer prSrv.Close()

	pr := postgrest.New(postgrest.Config{URL: prSrv.URL, ServiceKey: "svc"})
	vh := New(idempotency.New(idempotency.NewMemStore()), pr, nil)

	msg := model.VolumeJobMsg{
		RequestID: "req-retry",
		Command:   "create volume v7",
		ClusterID: 3,
		Arguments: rawArgs(t, map[string]any{"email": "u@example.com", "volume_id": "vol-retry"}),
	}
	if err := vh.handle(context.Background(), msg); err == nil {
		t.Fatal("expected retryable error on first provision failure")
	}
	if err := vh.handle(context.Background(), msg); err != nil {
		t.Fatalf("retry handle: %v", err)
	}
	if jobPosts != 2 {
		t.Fatalf("job POSTs = %d, want 2 (insert + conflict recovery)", jobPosts)
	}
	if jobPatch == nil || jobPatch["success"] != true {
		t.Fatalf("job patch after retry: %v", jobPatch)
	}
}
