package processanalytics_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/processanalytics"
	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	busmemory "github.com/thinkonmay/global-proxy/api/pkg/bus/memory"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

func TestPushAccepted(t *testing.T) {
	b := busmemory.New(nil)
	var mu sync.Mutex
	var published []model.AppUsageMsg
	bus.Subscribe(b, model.TopicAppUsage, "test-cap", func(_ context.Context, msg model.AppUsageMsg) error {
		mu.Lock()
		published = append(published, msg)
		mu.Unlock()
		return nil
	})

	h := processanalytics.New(b, nil)
	mux := http.NewServeMux()
	h.Register(mux)

	body := `{
		"user_email":"u@example.com",
		"runtime_session_id":"sess-1",
		"flush_reason":"interval",
		"flush_seq":3,
		"apps":[{"app_key":"game:elden-ring","duration_sec":120,"launch_count":2}]
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/analytics/process/push", strings.NewReader(body))
	req.Header.Set("cluster", "saigon2.thinkmay.net")
	req.Header.Set("node", "macro9")
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{}},
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d body=%q", rec.Code, rec.Body.String())
	}
	b.Wait()
	mu.Lock()
	defer mu.Unlock()
	if len(published) != 1 {
		t.Fatalf("published %d messages, want 1", len(published))
	}
	msg := published[0]
	if msg.UserEmail != "u@example.com" || msg.AppKey != "game:elden-ring" || msg.DurationSec != 120 {
		t.Fatalf("unexpected msg: %+v", msg)
	}
	if msg.Cluster != "saigon2.thinkmay.net" || msg.Node != "macro9" || msg.FlushSeq != 3 {
		t.Fatalf("unexpected headers mapped: %+v", msg)
	}
	if msg.Source != "process_analytics" {
		t.Fatalf("source = %q, want process_analytics", msg.Source)
	}
}

func TestPushPublishesOneMessagePerAppCDP1(t *testing.T) {
	b := busmemory.New(nil)
	var mu sync.Mutex
	var published []model.AppUsageMsg
	bus.Subscribe(b, model.TopicAppUsage, "test-cap", func(_ context.Context, msg model.AppUsageMsg) error {
		mu.Lock()
		published = append(published, msg)
		mu.Unlock()
		return nil
	})

	h := processanalytics.New(b, nil)
	mux := http.NewServeMux()
	h.Register(mux)

	body := `{
		"user_email":"u@example.com",
		"runtime_session_id":"sess-1",
		"apps":[
			{"app_key":"game:elden-ring","duration_sec":120,"launch_count":2},
			{"app_key":"fivem","duration_sec":30,"launch_count":1}
		]
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/analytics/process/push", strings.NewReader(body))
	req.Header.Set("cluster", "c1")
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{}}}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d body=%q", rec.Code, rec.Body.String())
	}
	b.Wait()
	mu.Lock()
	defer mu.Unlock()
	if len(published) != 2 {
		t.Fatalf("published %d messages, want 2", len(published))
	}
}

func TestPushRequiresMTLS(t *testing.T) {
	h := processanalytics.New(busmemory.New(nil), nil)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/analytics/process/push", strings.NewReader(`{"user_email":"u@example.com","runtime_session_id":"s","apps":[{"app_key":"x","duration_sec":1}]}`))
	req.Header.Set("cluster", "c")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestPushMissingFields(t *testing.T) {
	h := processanalytics.New(busmemory.New(nil), nil)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/analytics/process/push", strings.NewReader(`{"apps":[{"app_key":"x","duration_sec":1}]}`))
	req.Header.Set("cluster", "c")
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{}}}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestBlacklistRequiresMTLS(t *testing.T) {
	h := processanalytics.New(busmemory.New(nil), nil)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/analytics/process/blacklist", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestBlacklistReturnsConstantJSONCDP1(t *testing.T) {
	constantJSON := `{"exact":["svchost"],"prefixes":["microsoftedge_"],"suffixes":["crashhandler"]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/constant" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer test-service" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"value":` + constantJSON + `}]`))
	}))
	defer srv.Close()

	pr := postgrest.New(postgrest.Config{URL: srv.URL, ServiceKey: "test-service"})
	h := processanalytics.New(busmemory.New(nil), pr)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/analytics/process/blacklist", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{}}}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%q", rec.Code, rec.Body.String())
	}
	if strings.TrimSpace(rec.Body.String()) != constantJSON {
		t.Fatalf("body = %q, want %q", rec.Body.String(), constantJSON)
	}
}

func TestNewNilWhenBusDisabled(t *testing.T) {
	if processanalytics.New(nil, nil) != nil {
		t.Fatal("expected nil handler")
	}
}
