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
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

func TestVolumeHandlerCreateVolume(t *testing.T) {
	var mu sync.Mutex
	var jobPatch map[string]any
	pb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/collections/users/records":
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
	defer pb.Close()

	prSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rpc/get_cluster_secrets":
			_ = json.NewEncoder(w).Encode([]map[string]string{{
				"token": "admin-token",
				"url":   pb.URL,
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
	idem := idempotency.New(idempotency.NewMemStore())
	vh := newVolumeHandler(idem, pr)

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

func TestVolumeHandlerSkipsUnknownCommand(t *testing.T) {
	pr := postgrest.New(postgrest.Config{URL: "http://127.0.0.1:1"})
	vh := newVolumeHandler(idempotency.New(idempotency.NewMemStore()), pr)
	err := vh.handle(context.Background(), model.VolumeJobEnvelope{
		OutboxID: 2,
		Payload:  model.VolumeJobPayload{Command: "unknown"},
	})
	if err != nil {
		t.Fatalf("expected nil for unknown command, got %v", err)
	}
}

func TestURLQueryEscape(t *testing.T) {
	if urlQueryEscape(`a"b`) != `a%22b` {
		t.Fatal("escape failed")
	}
}
