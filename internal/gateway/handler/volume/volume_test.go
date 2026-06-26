package volume

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	busmemory "github.com/thinkonmay/global-proxy/api/pkg/bus/memory"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

// errBus is a bus.Client that always fails Publish (simulates JetStream unavailable).
type errBus struct{ err error }

func (e *errBus) Publish(context.Context, string, []byte) error               { return e.err }
func (e *errBus) Subscribe(string, string, bus.Handler, bus.SubscribeOptions) {}
func (e *errBus) Ping() error                                                 { return nil }
func (e *errBus) Close() error                                                { return nil }

var _ bus.Client = (*errBus)(nil)

func clusterSrv() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/clusters" {
			_ = json.NewEncoder(w).Encode([]map[string]any{{
				"id":     3,
				"domain": "saigon2.thinkmay.net",
				"secret": map[string]string{"url": "http://pb"},
			}})
			return
		}
		http.NotFound(w, r)
	}))
}

func TestCreateVolumePublishes(t *testing.T) {
	prSrv := clusterSrv()
	defer prSrv.Close()
	pr := postgrest.New(postgrest.Config{URL: prSrv.URL, ServiceKey: "svc"})
	eventBus := busmemory.New(nil)

	var mu sync.Mutex
	var got model.VolumeJobMsg
	bus.Subscribe(eventBus, model.TopicVolumeJob, "test", func(_ context.Context, m model.VolumeJobMsg) error {
		mu.Lock()
		got = m
		mu.Unlock()
		return nil
	})

	h := New(pr, eventBus)
	mux := http.NewServeMux()
	h.Register(mux)

	body := bytes.NewBufferString(`{"command":"create volume v7","cluster":3,"arguments":{"email":"u@x.com","volume_id":"v1"}}`)
	req := httptest.NewRequest(http.MethodPost, "/volume", body)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	eventBus.Wait()

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status: %d body: %s", rec.Code, rec.Body.String())
	}
	var out map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out["id"] == "" {
		t.Fatal("expected request id")
	}

	mu.Lock()
	defer mu.Unlock()
	if got.RequestID != out["id"] {
		t.Fatalf("published request_id %q != returned id %q", got.RequestID, out["id"])
	}
	if got.Command != "create volume v7" || got.ClusterID != 3 || got.TargetDomain != "saigon2.thinkmay.net" {
		t.Fatalf("published msg: %+v", got)
	}
}

func TestCreateVolumeRejectsUnknownCommand(t *testing.T) {
	prSrv := clusterSrv()
	defer prSrv.Close()
	h := New(postgrest.New(postgrest.Config{URL: prSrv.URL}), busmemory.New(nil))
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodPost, "/volume",
		bytes.NewBufferString(`{"command":"rm -rf","cluster":3}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestRegisterDisabledWithoutBus(t *testing.T) {
	h := New(nil, nil)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodPost, "/volume", bytes.NewBufferString(`{}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 (route not mounted), got %d", rec.Code)
	}
}

func TestCreateVolumePublishFailureReturns503(t *testing.T) {
	prSrv := clusterSrv()
	defer prSrv.Close()
	h := New(postgrest.New(postgrest.Config{URL: prSrv.URL}), &errBus{err: errors.New("jetstream unavailable")})
	mux := http.NewServeMux()
	h.Register(mux)

	body := bytes.NewBufferString(`{"command":"create volume v7","cluster":3,"arguments":{"email":"u@x.com"}}`)
	req := httptest.NewRequest(http.MethodPost, "/volume", body)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status: %d body: %s", rec.Code, rec.Body.String())
	}
	var out map[string]bool
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if !out["global_unavailable"] {
		t.Fatalf("body: %v", out)
	}
}

func TestCreateVolumeUnknownCluster(t *testing.T) {
	prSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/clusters" {
			_ = json.NewEncoder(w).Encode([]map[string]any{})
			return
		}
		http.NotFound(w, r)
	}))
	defer prSrv.Close()

	h := New(postgrest.New(postgrest.Config{URL: prSrv.URL}), busmemory.New(nil))
	mux := http.NewServeMux()
	h.Register(mux)

	body := bytes.NewBufferString(`{"command":"create volume v7","cluster":99}`)
	req := httptest.NewRequest(http.MethodPost, "/volume", body)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestCreateVolumeInvalidBody(t *testing.T) {
	h := New(postgrest.New(postgrest.Config{URL: "http://127.0.0.1:1"}), busmemory.New(nil))
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodPost, "/volume", bytes.NewBufferString(`not-json`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestCreateVolumeMissingRequiredFields(t *testing.T) {
	prSrv := clusterSrv()
	defer prSrv.Close()
	h := New(postgrest.New(postgrest.Config{URL: prSrv.URL}), busmemory.New(nil))
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodPost, "/volume", bytes.NewBufferString(`{"command":"create volume v7"}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
	}
}
