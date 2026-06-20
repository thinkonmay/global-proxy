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
	return NewServer(cache, "test-secret"), mr
}

func TestPushAndScrape(t *testing.T) {
	srv, _ := testServer(t)
	h := srv.Handler()

	push := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("cpu_usage 1\n"))
	push.Header.Set("Authorization", "test-secret")
	push.Header.Set("node", "worker-a")
	push.Header.Set("type", "node-exporter")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, push)
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
	if !bytes.Contains(body, []byte("cpu_usage 1")) {
		t.Fatalf("missing pushed metric: %s", body)
	}
	if !bytes.Contains(body, []byte(`thinkmay_node_up{node="worker-a"} 1`)) {
		t.Fatalf("missing node up metric: %s", body)
	}
}

func TestPushUnauthorized(t *testing.T) {
	srv, _ := testServer(t)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("x 1\n"))
	req.Header.Set("Authorization", "wrong")
	req.Header.Set("node", "worker-a")
	req.Header.Set("type", "node-exporter")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}
