package coraza

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDisabledPassesThrough(t *testing.T) {
	m, err := New(Config{Enabled: false})
	if err != nil {
		t.Fatal(err)
	}
	called := false
	h := m.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/rest/v1/stores", nil))
	if !called || rec.Code != http.StatusOK {
		t.Fatalf("expected pass-through, called=%v code=%d", called, rec.Code)
	}
}

func TestSkipPathBypassesEngine(t *testing.T) {
	m, err := New(Config{
		Enabled:          true,
		OWASPCRS:         false,
		RequestBodyLimit: 1 << 20,
		SkipPaths:        []string{"/storage/v1/"},
	})
	if err != nil {
		t.Fatal(err)
	}
	called := false
	h := m.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/storage/v1/object/large", strings.NewReader("payload")))
	if !called || rec.Code != http.StatusOK {
		t.Fatalf("skip path failed called=%v code=%d", called, rec.Code)
	}
}

func TestEngineBlocksOversizedBody(t *testing.T) {
	const limit = 200_000
	m, err := New(Config{
		Enabled:          true,
		OWASPCRS:         false,
		RequestBodyLimit: limit,
	})
	if err != nil {
		t.Fatal(err)
	}
	h := m.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	body := make([]byte, limit+1)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/rest/v1/stores", io.NopCloser(strings.NewReader(string(body))))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatalf("expected body limit rejection, got %d", rec.Code)
	}
}
