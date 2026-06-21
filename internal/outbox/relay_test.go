package outbox

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	busmemory "github.com/thinkonmay/global-proxy/api/pkg/bus/memory"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

func TestParsePayload(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{
		"command": "create volume v7",
		"job_id":  float64(42),
		"email":   "u@example.com",
	})
	p := ParsePayload(raw)
	if p.Command != "create volume v7" || p.JobID != 42 || p.Email != "u@example.com" {
		t.Fatalf("unexpected payload: %+v", p)
	}
}

func TestPollOncePublishesAndMarksPublished(t *testing.T) {
	var mu sync.Mutex
	marked := []int64{}
	released := []int64{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rpc/claim_unpublished_outbox":
			_ = json.NewEncoder(w).Encode([]Row{{
				ID:    7,
				Topic: "jobs.volume",
				Payload: json.RawMessage(`{"command":"create volume v7","job_id":1,"email":"a@b.c"}`),
			}})
		case "/rpc/mark_outbox_published":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			marked = append(marked, int64(body["p_id"].(float64)))
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		case "/rpc/release_outbox_claim":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			released = append(released, int64(body["p_id"].(float64)))
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	pr := postgrest.New(postgrest.Config{URL: srv.URL, ServiceKey: "svc"})
	eventBus := busmemory.New(nil)
	var got []model.VolumeJobEnvelope
	bus.Subscribe(eventBus, model.TopicVolumeJob, "test", func(_ context.Context, env model.VolumeJobEnvelope) error {
		got = append(got, env)
		return nil
	}, bus.WithConcurrency(1))

	if err := PollOnce(context.Background(), pr, eventBus, 10); err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	eventBus.Wait()
	if len(got) != 1 || got[0].OutboxID != 7 {
		t.Fatalf("published envelope: %+v", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(marked) != 1 || marked[0] != 7 {
		t.Fatalf("marked ids: %v", marked)
	}
	if len(released) != 0 {
		t.Fatalf("unexpected release: %v", released)
	}
}

func TestPollOnceReleasesClaimOnPublishFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rpc/claim_unpublished_outbox":
			_ = json.NewEncoder(w).Encode([]Row{{ID: 9, Topic: "jobs.volume", Payload: json.RawMessage(`{}`)}})
		case "/rpc/release_outbox_claim":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	pr := postgrest.New(postgrest.Config{URL: srv.URL, ServiceKey: "svc"})
	closed := busmemory.New(nil)
	_ = closed.Close()

	if err := PollOnce(context.Background(), pr, closed, 10); err == nil {
		t.Fatal("expected publish failure")
	}
}
