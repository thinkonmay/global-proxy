package handler

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

func TestNodeRuntimeSteamClaimSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rpc/claim_v1" {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), `"app_id":"570"`) {
			t.Fatalf("unexpected body: %s", body)
		}
		_, _ = w.Write([]byte(`[{"id":1,"username":"u","password":"p","depotKey":{}}]`))
	}))
	defer srv.Close()

	h := NewNodeRuntimeHandler(postgrest.New(postgrest.Config{URL: srv.URL, ServiceKey: "svc"}), "svc")
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/app-access/steam/claim", strings.NewReader(`{"app_id":"570","email":"u@example.com"}`))
	req.Header.Set("apikey", "svc")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d body: %s", rec.Code, rec.Body.String())
	}
	var rows []map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0]["username"] != "u" {
		t.Fatalf("rows: %v", rows)
	}
}

func TestNodeRuntimeKeepaliveRequiresServiceKey(t *testing.T) {
	h := NewNodeRuntimeHandler(postgrest.New(postgrest.Config{URL: "http://127.0.0.1:1", ServiceKey: "svc"}), "svc")
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/node/keepalive", strings.NewReader(`{"id":1}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestNodeRuntimeKeepaliveSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rpc/keepalive_v1" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`"true"`))
	}))
	defer srv.Close()

	h := NewNodeRuntimeHandler(postgrest.New(postgrest.Config{URL: srv.URL, ServiceKey: "svc"}), "svc")
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/node/keepalive", strings.NewReader(`{"id":42}`))
	req.Header.Set("Authorization", "Bearer svc")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d body: %s", rec.Code, rec.Body.String())
	}
	var resp string
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil || resp != "true" {
		t.Fatalf("body: %s err: %v", rec.Body.String(), err)
	}
}
