package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/thinkonmay/global-proxy/api/pkg/idempotency"
	"github.com/thinkonmay/global-proxy/api/pkg/pocketbase"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

func pbAuthHandler(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodPost && r.URL.Path == "/api/collections/_superusers/auth-with-password" {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"token":"admin-token"}`))
		return true
	}
	return false
}

func TestVolumeHandlerCreateVolume(t *testing.T) {
	var mu sync.Mutex
	var jobPatch map[string]any
	pbSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if pbAuthHandler(w, r) {
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/collections/users/records":
			if r.Header.Get("Authorization") != "Bearer admin-token" {
				t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"items": []map[string]string{{"id": "user-1"}},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/collections/volumes/records":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"id": "vol-1"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer pbSrv.Close()

	prSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rpc/get_cluster_secrets":
			_ = json.NewEncoder(w).Encode([]map[string]string{{
				"url": pbSrv.URL,
			}})
		default:
			if r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/job") {
				_ = json.NewDecoder(r.Body).Decode(&jobPatch)
				mu.Lock()
				w.WriteHeader(http.StatusNoContent)
				mu.Unlock()
				return
			}
			http.NotFound(w, r)
		}
	}))
	defer prSrv.Close()

	pr := postgrest.New(postgrest.Config{URL: prSrv.URL, ServiceKey: "svc"})
	pb := pocketbase.New(pocketbase.Config{URL: pbSrv.URL, Username: "admin@test.com", Password: "secret"})
	idem := idempotency.New(idempotency.NewMemStore())
	vh := newVolumeHandler(idem, pr, pb)

	err := vh.handle(context.Background(), model.VolumeJobEnvelope{
		OutboxID: 1,
		Payload: model.VolumeJobPayload{
			Command:   "create volume v7",
			JobID:     99,
			ClusterID: 3,
			Email:     "u@example.com",
			VolumeID:  "local-vol",
		},
	})
	if err != nil {
		t.Fatalf("handle: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if jobPatch == nil || jobPatch["success"] != true {
		t.Fatalf("job patch: %v", jobPatch)
	}
}

func TestVolumeHandlerUpdateVolume(t *testing.T) {
	var mu sync.Mutex
	var jobPatch map[string]any
	var patchedCfg map[string]any
	pbSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if pbAuthHandler(w, r) {
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/collections/users/records":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"items": []map[string]string{{"id": "user-1"}},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/api/collections/volumes/records":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"items": []map[string]any{{
					"id": "vol-rec-1",
					"configuration": map[string]any{
						"email":    "u@example.com",
						"template": "win11",
						"disk":     map[string]any{"size": 50},
						"plan":     "pro",
					},
				}},
			})
		case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/api/collections/volumes/records/"):
			_ = json.NewDecoder(r.Body).Decode(&patchedCfg)
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]string{"id": "vol-rec-1"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer pbSrv.Close()

	prSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rpc/get_cluster_secrets":
			_ = json.NewEncoder(w).Encode([]map[string]string{{
				"url": pbSrv.URL,
			}})
		default:
			if r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/job") {
				_ = json.NewDecoder(r.Body).Decode(&jobPatch)
				mu.Lock()
				w.WriteHeader(http.StatusNoContent)
				mu.Unlock()
				return
			}
			http.NotFound(w, r)
		}
	}))
	defer prSrv.Close()

	pr := postgrest.New(postgrest.Config{URL: prSrv.URL, ServiceKey: "svc"})
	pb := pocketbase.New(pocketbase.Config{URL: pbSrv.URL, Username: "admin@test.com", Password: "secret"})
	vh := newVolumeHandler(idempotency.New(idempotency.NewMemStore()), pr, pb)

	cfg, _ := json.Marshal(map[string]any{"tier": "premium"})
	err := vh.handle(context.Background(), model.VolumeJobEnvelope{
		OutboxID: 3,
		Payload: model.VolumeJobPayload{
			Command:       "update volume v7",
			JobID:         100,
			ClusterID:     3,
			Email:         "u@example.com",
			Configuration: cfg,
		},
	})
	if err != nil {
		t.Fatalf("handle: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if jobPatch == nil || jobPatch["success"] != true {
		t.Fatalf("job patch: %v", jobPatch)
	}
	merged, ok := patchedCfg["configuration"].(map[string]any)
	if !ok {
		t.Fatalf("patch configuration: %v", patchedCfg)
	}
	if merged["tier"] != "premium" || merged["template"] != "win11" {
		t.Fatalf("merged configuration: %v", merged)
	}
}

func TestVolumeHandlerSkipsUnknownCommand(t *testing.T) {
	pr := postgrest.New(postgrest.Config{URL: "http://127.0.0.1:1"})
	pb := pocketbase.New(pocketbase.Config{URL: "http://127.0.0.1:1", Username: "a", Password: "b"})
	vh := newVolumeHandler(idempotency.New(idempotency.NewMemStore()), pr, pb)
	err := vh.handle(context.Background(), model.VolumeJobEnvelope{
		OutboxID: 2,
		Payload:  model.VolumeJobPayload{Command: "unknown"},
	})
	if err != nil {
		t.Fatalf("expected nil for unknown command, got %v", err)
	}
}
