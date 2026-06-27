package mail

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/auth"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/testsupport"
	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	busmemory "github.com/thinkonmay/global-proxy/api/pkg/bus/memory"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

func TestListMailRequiresAuth(t *testing.T) {
	h := New(postgrest.New(postgrest.Config{URL: "http://unused"}), busmemory.New(nil), "svc", nil)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/mail", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", rec.Code)
	}
}

func TestListMailReturnsItems(t *testing.T) {
	auth.ConfigureGoTrueAuth("test-secret")
	t.Cleanup(func() { auth.ConfigureGoTrueAuth("") })

	prSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/mail") {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{{
			"title":     "Welcome",
			"subject":   "Welcome",
			"created":   "2026-06-27T10:00:00Z",
			"finalHTML": "<p>Hi</p>",
		}})
	}))
	t.Cleanup(prSrv.Close)

	h := New(postgrest.New(postgrest.Config{URL: prSrv.URL, ServiceKey: "svc"}), busmemory.New(nil), "svc", nil)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/mail", nil)
	req.Header.Set("Authorization", "Bearer "+testsupport.GoTrueJWT(t, "test-secret", "uid-1", "user@example.com"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0]["finalHTML"] != "<p>Hi</p>" || out[0]["content"] != "<p>Hi</p>" {
		t.Fatalf("unexpected body: %v", out)
	}
}

func TestEnqueueRequiresServiceKey(t *testing.T) {
	b := busmemory.New(nil)
	h := New(postgrest.New(postgrest.Config{URL: "http://unused"}), b, "svc", nil)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/mail", strings.NewReader(`{"email":"u@example.com","final_html":"<p>x</p>"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", rec.Code)
	}
}

func TestEnqueuePublishesJob(t *testing.T) {
	b := busmemory.New(nil)
	var mu sync.Mutex
	var published []model.MailJobMsg
	bus.Subscribe(b, model.TopicMailJob, "test-mail-cap", func(_ context.Context, msg model.MailJobMsg) error {
		mu.Lock()
		published = append(published, msg)
		mu.Unlock()
		return nil
	})

	h := New(postgrest.New(postgrest.Config{URL: "http://unused"}), b, "svc", nil)
	mux := http.NewServeMux()
	h.Register(mux)

	body := `{"email":"user@example.com","title":"T","final_html":"<p>Hi</p>","send_email":true}`
	req := httptest.NewRequest(http.MethodPost, "/v1/mail", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer svc")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	b.Wait()
	mu.Lock()
	defer mu.Unlock()
	if len(published) != 1 || published[0].Email != "user@example.com" {
		t.Fatalf("published = %#v", published)
	}
}
