package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	busmemory "github.com/thinkonmay/global-proxy/api/pkg/bus/memory"
)

func TestHealth(t *testing.T) {
	h := NewHandler(nil)
	mux := http.NewServeMux()
	h.Register(mux, RouteOptions{})

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d", rec.Code)
	}
	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["status"] != "ok" {
		t.Fatalf("body: %v", body)
	}
}

func TestCreateJobPublishes(t *testing.T) {
	bus := busmemory.New(nil)
	h := NewHandler(bus)
	mux := http.NewServeMux()
	h.Register(mux, RouteOptions{DevJobs: true})

	body := bytes.NewBufferString(`{"command":"ping","arguments":{}}`)
	req := httptest.NewRequest(http.MethodPost, "/jobs", body)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	bus.Wait()

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status: %d body: %s", rec.Code, rec.Body.String())
	}
	var out map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out["id"] == "" {
		t.Fatal("expected job id")
	}
}

func TestCreateJobDisabledWithoutDevFlag(t *testing.T) {
	bus := busmemory.New(nil)
	h := NewHandler(bus)
	mux := http.NewServeMux()
	h.Register(mux, RouteOptions{})

	req := httptest.NewRequest(http.MethodPost, "/jobs", bytes.NewBufferString(`{"command":"ping"}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}
