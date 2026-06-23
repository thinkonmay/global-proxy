package upstream

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/thinkonmay/global-proxy/api/config"
)

func TestRybbitIngestProxiedOnPublicHost(t *testing.T) {
	var gotPath, gotMethod string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		_, _ = io.WriteString(w, "ok")
	}))
	defer backend.Close()

	mux := http.NewServeMux()
	cfg := &config.Config{
		Admin: config.Admin{
			Upstreams: config.AdminUpstreams{RybbitBackend: backend.URL},
		},
	}
	RegisterRybbitIngest(mux, cfg, http.DefaultTransport)

	for _, tc := range []struct {
		method string
		path   string
		want   string
	}{
		{http.MethodPost, "/api/track", "/api/track"},
		{http.MethodPost, "/api/identify", "/api/identify"},
		{http.MethodGet, "/api/script.js", "/api/script.js"},
		{http.MethodGet, "/api/site/tracking-config/1", "/api/site/tracking-config/1"},
		{http.MethodPost, "/api/session-replay/record/1", "/api/session-replay/record/1"},
	} {
		gotPath, gotMethod = "", ""
		req := httptest.NewRequest(tc.method, tc.path, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s %s: status=%d body=%q", tc.method, tc.path, rec.Code, rec.Body.String())
		}
		if gotPath != tc.want || gotMethod != tc.method {
			t.Fatalf("%s %s: upstream got %s %s, want %s %s", tc.method, tc.path, gotMethod, gotPath, tc.method, tc.want)
		}
	}
}
