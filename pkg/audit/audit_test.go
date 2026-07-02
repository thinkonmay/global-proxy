package audit

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/grpc/metadata"
)

func TestMiddlewareRequestID(t *testing.T) {
	rec := NewRecorder("")
	var seenID string
	h := Middleware(rec)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenID = RequestID(r.Context())
		w.WriteHeader(http.StatusCreated)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/billing/wallet", nil)
	req.Header.Set("X-Request-ID", "test-req-1")
	recorder := httptest.NewRecorder()
	h.ServeHTTP(recorder, req)

	if seenID != "test-req-1" {
		t.Fatalf("context request_id = %q", seenID)
	}
	if got := recorder.Header().Get("X-Request-ID"); got != "test-req-1" {
		t.Fatalf("response request_id = %q", got)
	}
}

func TestStatusWriterImplementsFlusher(t *testing.T) {
	rec := NewRecorder("")
	var flusherOK bool
	h := Middleware(rec)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, flusherOK = w.(http.Flusher)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/event/payment", nil)
	recorder := httptest.NewRecorder()
	h.ServeHTTP(recorder, req)

	if !flusherOK {
		t.Fatal("statusWriter must implement http.Flusher for SSE streaming handlers")
	}
}

func TestMiddlewareGeneratesRequestID(t *testing.T) {
	rec := NewRecorder("")
	var seenID string
	h := Middleware(rec)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenID = RequestID(r.Context())
	}))

	req := httptest.NewRequest(http.MethodPost, "/v1/runtime/close", nil)
	recorder := httptest.NewRecorder()
	h.ServeHTTP(recorder, req)

	if seenID == "" {
		t.Fatal("expected generated request_id")
	}
	if got := recorder.Header().Get("X-Request-ID"); got != seenID {
		t.Fatalf("header %q != context %q", got, seenID)
	}
}

func TestClientRecordEvents(t *testing.T) {
	var bulkBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/_bulk" {
			http.NotFound(w, r)
			return
		}
		b, _ := io.ReadAll(r.Body)
		bulkBody = string(b)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"errors":false}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
	ev := newEvent("admin.otp_verified", "admin")
	ev.RequestID = "req-1"
	ev.UserEmail = "ops@example.com"
	ev.Route = "/admin/otp/verify"
	if err := c.RecordEvents(context.Background(), []Event{ev}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(bulkBody, "audit-logs-") {
		t.Fatalf("expected audit index in bulk body: %s", bulkBody)
	}
	if !strings.Contains(bulkBody, "admin.otp_verified") {
		t.Fatalf("expected action in bulk body: %s", bulkBody)
	}
}

func TestRedactSecrets(t *testing.T) {
	s := `Bearer eyJhbGciOiJIUzI1NiJ9.abc.def and "code":"123456"`
	out := redactSecrets(s)
	if strings.Contains(out, "eyJ") {
		t.Fatalf("jwt not redacted: %q", out)
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Fatalf("expected redaction markers: %q", out)
	}
}

func TestOutgoingGRPCMetadata(t *testing.T) {
	ctx := WithRequestID(context.Background(), "trace-abc")
	out := OutgoingGRPCMetadata(ctx)
	md, ok := metadata.FromOutgoingContext(out)
	if !ok || len(md.Get(MetadataRequestID)) != 1 || md.Get(MetadataRequestID)[0] != "trace-abc" {
		t.Fatalf("unexpected metadata: %v ok=%v", md, ok)
	}
}
