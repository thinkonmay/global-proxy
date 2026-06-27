package metricsagg

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
)

func testServer(t *testing.T) (*Server, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mr.Close)
	cache, err := NewCache("redis://"+mr.Addr()+"/1", 90)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cache.Close() })
	return NewServer(cache), mr
}

func TestPushAndScrape(t *testing.T) {
	srv, _ := testServer(t)
	h := srv.ScrapeHandler()

	push := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("cpu_usage 1\n"))
	push.Header.Set("node", "worker-a")
	push.Header.Set("type", "node-exporter")
	rec := httptest.NewRecorder()
	srv.HandlePush(rec, push)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("push status = %d, want 202", rec.Code)
	}

	scrape := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, scrape)
	if rec.Code != http.StatusOK {
		t.Fatalf("scrape status = %d", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	if !bytes.Contains(body, []byte(`cpu_usage{node="worker-a"} 1`)) {
		t.Fatalf("missing pushed metric: %s", body)
	}
	if !bytes.Contains(body, []byte(`thinkmay_node_up{node="worker-a"} 1`)) {
		t.Fatalf("missing node up metric: %s", body)
	}
}

func TestRequireVirtdaemonMTLS(t *testing.T) {
	called := false
	handler := RequireVirtdaemonMTLS(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusAccepted)
	})
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusUnauthorized || called {
		t.Fatalf("expected 401 without TLS client cert, got %d called=%v", rec.Code, called)
	}
}

func TestInternalNodes(t *testing.T) {
	srv, _ := testServer(t)
	h := srv.ScrapeHandler()
	push := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"Hostname":"worker-a"}`))
	push.Header.Set("node", "worker-a")
	push.Header.Set("type", "info")
	rec := httptest.NewRecorder()
	srv.HandlePush(rec, push)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("push status = %d", rec.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/internal/nodes", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("nodes status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "worker-a") {
		t.Fatalf("body = %s", rec.Body.String())
	}
}
