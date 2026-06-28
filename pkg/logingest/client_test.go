package logingest_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/thinkonmay/global-proxy/api/pkg/logingest"
)

func TestNewClientDisabled(t *testing.T) {
	if c := logingest.NewClient("", 0); c.Enabled() {
		t.Fatal("empty url should be disabled")
	}
}

func TestIndexDocument(t *testing.T) {
	var bulkBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bulkBody = string(b)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"errors":false}`))
	}))
	defer srv.Close()

	client := logingest.NewClient(srv.URL, 1<<20)
	err := client.IndexDocument(context.Background(), map[string]any{
		"@timestamp": "2026-06-28T15:00:00Z",
		"component":  "virtdaemon",
		"message":    "daemon started",
		"node":       "macro9",
	})
	if err != nil {
		t.Fatalf("IndexDocument: %v", err)
	}
	if !strings.Contains(bulkBody, "worker-logs-2026.06.28") {
		t.Fatalf("missing index in bulk: %s", bulkBody)
	}
	if !strings.Contains(bulkBody, "daemon started") {
		t.Fatalf("missing message in bulk: %s", bulkBody)
	}
}

func TestIndexNDJSONBulk(t *testing.T) {
	var bulkBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/_bulk" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		b, _ := io.ReadAll(r.Body)
		bulkBody = string(b)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"errors":false}`))
	}))
	defer srv.Close()

	client := logingest.NewClient(srv.URL, 1<<20)
	doc := map[string]any{
		"@timestamp": "2026-06-28T12:00:00Z",
		"component":  "proxy",
		"message":    "kvm host tune: ok",
		"node":       "macro9",
	}
	line, _ := json.Marshal(doc)
	body := string(line) + "\n"
	if err := client.IndexNDJSON(context.Background(), []byte(body)); err != nil {
		t.Fatalf("IndexNDJSON: %v", err)
	}
	if !strings.Contains(bulkBody, "worker-logs-2026.06.28") {
		t.Fatalf("bulk missing index: %s", bulkBody)
	}
	if !strings.Contains(bulkBody, "kvm host tune") {
		t.Fatalf("bulk missing message: %s", bulkBody)
	}
}

func TestIndexNDJSONMultipleLines(t *testing.T) {
	linesIndexed := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		linesIndexed = strings.Count(string(b), `"index"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"errors":false}`))
	}))
	defer srv.Close()

	client := logingest.NewClient(srv.URL, 1<<20)
	body := strings.Join([]string{
		`{"@timestamp":"2026-06-28T12:00:00Z","component":"virtdaemon","message":"one"}`,
		`{"@timestamp":"2026-06-28T12:00:01Z","component":"dmesg","message":"two"}`,
	}, "\n") + "\n"
	if err := client.IndexNDJSON(context.Background(), []byte(body)); err != nil {
		t.Fatalf("IndexNDJSON: %v", err)
	}
	if linesIndexed != 2 {
		t.Fatalf("indexed actions = %d, want 2", linesIndexed)
	}
}

func TestIndexNDJSONSkipsInvalidLines(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if strings.Contains(string(b), "not-json") {
			t.Fatal("invalid line should be skipped")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"errors":false}`))
	}))
	defer srv.Close()

	client := logingest.NewClient(srv.URL, 1<<20)
	body := "not-json\n" + `{"@timestamp":"2026-06-28T12:00:00Z","component":"proxy","message":"ok"}` + "\n"
	if err := client.IndexNDJSON(context.Background(), []byte(body)); err != nil {
		t.Fatalf("IndexNDJSON: %v", err)
	}
}

func TestRedactSecrets(t *testing.T) {
	var bulkBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bulkBody = string(b)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"errors":false}`))
	}))
	defer srv.Close()

	client := logingest.NewClient(srv.URL, 1<<20)
	doc := map[string]any{
		"@timestamp": "2026-06-28T12:00:00Z",
		"component":  "virtdaemon",
		"message":    "token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature",
	}
	line, _ := json.Marshal(doc)
	if err := client.IndexNDJSON(context.Background(), line); err != nil {
		t.Fatalf("IndexNDJSON: %v", err)
	}
	if strings.Contains(bulkBody, "eyJhbGci") {
		t.Fatalf("jwt not redacted: %s", bulkBody)
	}
	if !strings.Contains(bulkBody, "[REDACTED]") {
		t.Fatalf("expected [REDACTED] in bulk: %s", bulkBody)
	}
}

func TestIndexNDJSONEmptyBody(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := logingest.NewClient(srv.URL, 1<<20)
	if err := client.IndexNDJSON(context.Background(), []byte("\n\n")); err != nil {
		t.Fatalf("IndexNDJSON: %v", err)
	}
	if called {
		t.Fatal("expected no ES call for empty NDJSON body")
	}
}
