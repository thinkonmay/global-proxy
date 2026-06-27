package mail

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	busmemory "github.com/thinkonmay/global-proxy/api/pkg/bus/memory"
	"github.com/thinkonmay/global-proxy/api/config"
	pkgmail "github.com/thinkonmay/global-proxy/api/pkg/mail"
	"github.com/thinkonmay/global-proxy/api/pkg/idempotency"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

type stubSender struct {
	mu    sync.Mutex
	calls int
	id    string
	err   error
}

func (s *stubSender) Send(context.Context, pkgmail.SendParams) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.err != nil {
		return "", s.err
	}
	if s.id == "" {
		s.id = "re_test"
	}
	return s.id, nil
}

func TestMailHandlerSendsAndPatches(t *testing.T) {
	var mu sync.Mutex
	patches := []map[string]any{}
	sender := &stubSender{}
	prSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/mail"):
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode([]map[string]any{{"id": 7, "status": "pending"}})
		case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/mail"):
			var patch map[string]any
			_ = json.NewDecoder(r.Body).Decode(&patch)
			mu.Lock()
			patches = append(patches, patch)
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(prSrv.Close)

	pr := postgrest.New(postgrest.Config{URL: prSrv.URL, ServiceKey: "svc"})
	h := New(idempotency.New(idempotency.NewMemStore()), pr, config.Mail{Enabled: true})
	h.sender = sender

	b := busmemory.New(nil)
	h.Init(b)
	if err := pkgmail.Publish(context.Background(), b, model.MailJobMsg{
		RequestID: "req-1",
		Email:     "user@example.com",
		Title:     "Hello",
		Subject:   "Hello",
		FinalHTML: "<p>Hi</p>",
		SendEmail: true,
		InApp:     true,
	}); err != nil {
		t.Fatal(err)
	}
	b.Wait()

	sender.mu.Lock()
	calls := sender.calls
	sender.mu.Unlock()
	if calls != 1 {
		t.Fatalf("send calls = %d, want 1", calls)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(patches) != 1 || patches[0]["status"] != "sent" {
		t.Fatalf("patches = %#v, want status sent", patches)
	}
}

func TestMailHandlerDuplicateDeliverySingleSend(t *testing.T) {
	var mu sync.Mutex
	inserts := 0
	patches := 0
	sender := &stubSender{}
	prSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/mail"):
			mu.Lock()
			inserts++
			mu.Unlock()
			if inserts == 1 {
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode([]map[string]any{{"id": 9, "status": "pending"}})
				return
			}
			w.WriteHeader(http.StatusConflict)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/mail"):
			_ = json.NewEncoder(w).Encode([]map[string]any{{"id": 9, "status": "pending"}})
		case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/mail"):
			mu.Lock()
			patches++
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(prSrv.Close)

	pr := postgrest.New(postgrest.Config{URL: prSrv.URL, ServiceKey: "svc"})
	idem := idempotency.New(idempotency.NewMemStore())
	h := New(idem, pr, config.Mail{Enabled: true})
	h.sender = sender

	msg := model.MailJobMsg{
		RequestID: "req-dup",
		Email:     "user@example.com",
		Title:     "Dup",
		FinalHTML: "<p>x</p>",
		SendEmail: true,
	}
	if err := h.handle(context.Background(), msg); err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := h.handle(context.Background(), msg); err != nil {
		t.Fatalf("second: %v", err)
	}

	sender.mu.Lock()
	calls := sender.calls
	sender.mu.Unlock()
	if calls != 1 {
		t.Fatalf("send calls = %d, want 1", calls)
	}
	mu.Lock()
	defer mu.Unlock()
	if patches != 1 {
		t.Fatalf("patches = %d, want 1", patches)
	}
}

func TestMailHandlerInAppOnlySkipsResend(t *testing.T) {
	sender := &stubSender{}
	var patch map[string]any
	prSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/mail"):
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode([]map[string]any{{"id": 3, "status": "pending"}})
		case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/mail"):
			_ = json.NewDecoder(r.Body).Decode(&patch)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(prSrv.Close)

	pr := postgrest.New(postgrest.Config{URL: prSrv.URL, ServiceKey: "svc"})
	h := New(idempotency.New(idempotency.NewMemStore()), pr, config.Mail{})
	h.sender = sender

	if err := h.handle(context.Background(), model.MailJobMsg{
		RequestID: "req-inapp",
		Email:     "user@example.com",
		Title:     "Notice",
		FinalHTML: "<p>in app</p>",
		SendEmail: false,
		InApp:     true,
	}); err != nil {
		t.Fatal(err)
	}
	if patch["status"] != "skipped" {
		t.Fatalf("status = %v, want skipped", patch["status"])
	}
	if sender.calls != 0 {
		t.Fatalf("send calls = %d, want 0", sender.calls)
	}
}
