package cdp_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	gwcdp "github.com/thinkonmay/global-proxy/api/internal/gateway/handler/cdp"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

func TestAppendEventInvalidKindCDP3b(t *testing.T) {
	h := gwcdp.New(postgrest.New(postgrest.Config{URL: "http://unused"}), http.DefaultTransport)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/analytics/cdp/event", strings.NewReader(`{"kind":"Bad Kind","payload":{}}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 401 or 400", rec.Code)
	}
}

func TestRegisterNilSafeCDP3b(t *testing.T) {
	var h *gwcdp.Handler
	mux := http.NewServeMux()
	h.Register(mux)
}
