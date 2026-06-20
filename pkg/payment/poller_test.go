package payment

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

func TestPollerTickUpdatesStripeTransaction(t *testing.T) {
	var patchMu sync.Mutex
	var patchedStatus string

	stripeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/checkout/sessions/cs_test_123" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"payment_status": "paid"})
	}))
	t.Cleanup(stripeSrv.Close)

	prSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/constant":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"name": "stripe", "value": map[string]any{"secret_key": "sk_test"}},
			})
		case r.URL.Path == "/transactions" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode([]map[string]any{{
				"id": float64(42), "provider": "STRIPE", "status": "PENDING",
				"data":      map[string]any{"id": "cs_test_123"},
				"expire_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
			}})
		case r.URL.Path == "/transactions" && r.Method == http.MethodPatch:
			patchMu.Lock()
			if id := r.URL.Query().Get("id"); id != "eq.42" {
				t.Errorf("patch filter = %q, want eq.42", id)
			}
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			patchedStatus, _ = body["status"].(string)
			patchMu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(prSrv.Close)

	pr := postgrest.New(postgrest.Config{URL: prSrv.URL, ServiceKey: "svc"})
	p := NewPoller(pr, Config{PollEvery: time.Minute}, nil)
	stripeHost := strings.TrimPrefix(stripeSrv.URL, "http://")
	p.http = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.Host == "api.stripe.com" {
				req.URL.Scheme = "http"
				req.URL.Host = stripeHost
			}
			return http.DefaultTransport.RoundTrip(req)
		}),
		Timeout: 5 * time.Second,
	}

	p.tickPoll(context.Background())

	patchMu.Lock()
	defer patchMu.Unlock()
	if patchedStatus != "PAID" {
		t.Errorf("patched status = %q, want PAID", patchedStatus)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}
