package logingest_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	handler "github.com/thinkonmay/global-proxy/api/internal/gateway/handler/logingest"
	eslog "github.com/thinkonmay/global-proxy/api/pkg/logingest"
)

func TestHandlerPushAccepted(t *testing.T) {
	var indexed []byte
	es := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		indexed = b
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"errors":false}`))
	}))
	defer es.Close()

	h := handler.New(eslog.NewClient(es.URL, 1<<20))
	doc := map[string]any{
		"@timestamp": "2026-06-28T12:00:00Z",
		"component":  "dmesg",
		"message":    "vfio-pci fault",
	}
	line, _ := json.Marshal(doc)
	req := httptest.NewRequest(http.MethodPost, "/v1/logs/push", strings.NewReader(string(line)+"\n"))
	req.Header.Set("node", "macro9")
	rec := httptest.NewRecorder()

	h.Push(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d body=%q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(string(indexed), "vfio-pci fault") {
		t.Fatalf("ES bulk missing message: %s", indexed)
	}
}

func TestHandlerPushMissingNode(t *testing.T) {
	h := handler.New(eslog.NewClient("http://unused", 1<<20))
	req := httptest.NewRequest(http.MethodPost, "/v1/logs/push", strings.NewReader("{}\n"))
	rec := httptest.NewRecorder()
	h.Push(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestHandlerPushIndexFailure(t *testing.T) {
	es := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer es.Close()

	h := handler.New(eslog.NewClient(es.URL, 1<<20))
	req := httptest.NewRequest(http.MethodPost, "/v1/logs/push", strings.NewReader(`{"@timestamp":"2026-06-28T12:00:00Z","component":"proxy","message":"x"}`+"\n"))
	req.Header.Set("node", "macro9")
	rec := httptest.NewRecorder()
	h.Push(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
}

func TestHandlerNewNilWhenDisabled(t *testing.T) {
	if handler.New(nil) != nil {
		t.Fatal("expected nil handler")
	}
	if handler.New(eslog.NewClient("", 0)) != nil {
		t.Fatal("expected nil handler for disabled client")
	}
}

func TestRegisterRequiresMTLS(t *testing.T) {
	es := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer es.Close()

	mux := http.NewServeMux()
	h := handler.New(eslog.NewClient(es.URL, 1<<20))
	h.Register(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/logs/push", strings.NewReader("{}\n"))
	req.Header.Set("node", "macro9")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 without client cert", rec.Code)
	}
}
