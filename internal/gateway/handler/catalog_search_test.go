package handler

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

func TestSearchStoresBatchEmptyTexts(t *testing.T) {
	h := NewCatalogHandler(postgrest.New(postgrest.Config{URL: "http://127.0.0.1:1", ServiceKey: "svc"}))
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/search/stores", bytes.NewBufferString(`{"texts":[]}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != `{"data":[]}`+"\n" && rec.Body.String() != `{"data":[]}` {
		if !bytes.Contains(rec.Body.Bytes(), []byte(`"data":[]`)) {
			t.Fatalf("body=%s", rec.Body.String())
		}
	}
}

func TestSearchStoresBatchMissingTextsField(t *testing.T) {
	h := NewCatalogHandler(postgrest.New(postgrest.Config{URL: "http://127.0.0.1:1", ServiceKey: "svc"}))
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/search/stores", bytes.NewBufferString(`{}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for empty texts, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSearchStoresBatchMalformedBody(t *testing.T) {
	h := NewCatalogHandler(postgrest.New(postgrest.Config{URL: "http://127.0.0.1:1", ServiceKey: "svc"}))
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/search/stores", bytes.NewBufferString(`not-json`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for malformed body, got %d", rec.Code)
	}
}
