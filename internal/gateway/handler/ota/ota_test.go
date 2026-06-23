package ota

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

func TestOTAPublishReleaseSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rpc/publish_binary_release" {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), `"p_name":"proxy_binary"`) {
			t.Fatalf("unexpected body: %s", body)
		}
		_, _ = w.Write([]byte(`42`))
	}))
	defer srv.Close()

	h := New(postgrest.New(postgrest.Config{URL: srv.URL, ServiceKey: "svc"}), "svc")
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/ota/releases", strings.NewReader(`{
		"name":"proxy_binary",
		"md5":"abc",
		"storage_path":"proxy_binary/2026-01-01/abc/file",
		"public_url":"https://example/storage/file",
		"channel":"verified"
	}`))
	req.Header.Set("apikey", "svc")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d body: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if string(out.Data) != "42" {
		t.Fatalf("data: %s", out.Data)
	}
}

func TestOTAPublishReleaseRequiresServiceKey(t *testing.T) {
	h := New(postgrest.New(postgrest.Config{URL: "http://127.0.0.1:1", ServiceKey: "svc"}), "svc")
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/ota/releases", strings.NewReader(`{"name":"x","md5":"y","storage_path":"z","public_url":"u"}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}
