package catalog

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

func requestWithClientCert(method, target string, body io.Reader) *http.Request {
	req := httptest.NewRequest(method, target, body)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: "the-red:ops_at_example.com"}}},
	}
	return req
}

func TestPutStoreDepotKeysRequiresMTLS(t *testing.T) {
	h := New(postgrest.New(postgrest.Config{URL: "http://127.0.0.1:1"}), nil)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodPut, "/v1/catalog/stores/570/depot-keys", strings.NewReader(`{"depotkey":{"570":"abc"}}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d body: %s", rec.Code, rec.Body.String())
	}
}

func TestPutStoreDepotKeysRejectsVirtdaemonCert(t *testing.T) {
	h := New(postgrest.New(postgrest.Config{URL: "http://127.0.0.1:1"}), nil)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodPut, "/v1/catalog/stores/570/depot-keys", strings.NewReader(`{"depotkey":{"570":"abc"}}`))
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: "worker-node"}}},
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body: %s", rec.Code, rec.Body.String())
	}
}

func TestPutStoreDepotKeysSuccess(t *testing.T) {
	var gotArgs map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rpc/upsert_store_depot_keys_v1" {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotArgs)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	h := New(postgrest.New(postgrest.Config{URL: srv.URL, ServiceKey: "svc"}), nil)
	mux := http.NewServeMux()
	h.Register(mux)

	req := requestWithClientCert(http.MethodPut, "/v1/catalog/stores/570/depot-keys", strings.NewReader(`{"depotkey":{"570":"depot-key"}}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status: %d body: %s", rec.Code, rec.Body.String())
	}
	if gotArgs["store_id"] != float64(570) {
		t.Fatalf("store_id: %v", gotArgs["store_id"])
	}
}

func TestEnsureStoreSuccess(t *testing.T) {
	var gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	h := New(postgrest.New(postgrest.Config{URL: srv.URL, ServiceKey: "svc"}), nil)
	mux := http.NewServeMux()
	h.Register(mux)

	req := requestWithClientCert(http.MethodPost, "/v1/catalog/stores/570", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status: %d body: %s", rec.Code, rec.Body.String())
	}
	if gotMethod != http.MethodPost || gotPath != "/stores" {
		t.Fatalf("upstream: %s %s", gotMethod, gotPath)
	}
}

func TestPatchStoreDownloadsSuccess(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || r.URL.Path != "/stores" {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	h := New(postgrest.New(postgrest.Config{URL: srv.URL, ServiceKey: "svc"}), nil)
	mux := http.NewServeMux()
	h.Register(mux)

	req := requestWithClientCert(http.MethodPatch, "/v1/catalog/stores/570/downloads", strings.NewReader(`{"download":[{"url":"https://example.com"}]}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status: %d body: %s", rec.Code, rec.Body.String())
	}
	if gotBody["download"] == nil {
		t.Fatalf("download not sent: %v", gotBody)
	}
}
