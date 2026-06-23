package adminhost

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestGrafanaSessionNeedsMint(t *testing.T) {
	now := time.Now().Unix()
	tests := []struct {
		name string
		req  *http.Request
		want bool
	}{
		{
			name: "GET / without cookies",
			req:  httptest.NewRequest(http.MethodGet, "/", nil),
			want: true,
		},
		{
			name: "GET /apis skipped",
			req:  httptest.NewRequest(http.MethodGet, "/apis/foo", nil),
			want: false,
		},
		{
			name: "POST skipped",
			req:  httptest.NewRequest(http.MethodPost, "/", nil),
			want: false,
		},
		{
			name: "valid session pair",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.AddCookie(&http.Cookie{Name: "grafana_session", Value: "abc"})
				r.AddCookie(&http.Cookie{Name: grafanaSessionExpiryCookie, Value: strconv.FormatInt(now+3600, 10)})
				return r
			}(),
			want: false,
		},
		{
			name: "expired session",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.AddCookie(&http.Cookie{Name: "grafana_session", Value: "abc"})
				r.AddCookie(&http.Cookie{Name: grafanaSessionExpiryCookie, Value: strconv.FormatInt(now-10, 10)})
				return r
			}(),
			want: true,
		},
		{
			name: "session without expiry cookie",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.AddCookie(&http.Cookie{Name: "grafana_session", Value: "abc"})
				return r
			}(),
			want: true,
		},
	}

	m := &grafanaSessionMiddleware{}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := m.needsMint(tc.req); got != tc.want {
				t.Fatalf("needsMint() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestGrafanaSessionMiddlewareMintsAndRedirects(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/login" {
			t.Fatalf("unexpected mint path: %s", r.URL.Path)
		}
		if got := r.Header.Get(grafanaProxyUserHeader); got != "admin" {
			t.Fatalf("X-WEBAUTH-USER = %q", got)
		}
		http.SetCookie(w, &http.Cookie{Name: "grafana_session", Value: "minted", Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: grafanaSessionExpiryCookie, Value: strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10), Path: "/"})
		w.WriteHeader(http.StatusFound)
	}))
	defer upstream.Close()

	var proxied bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied = true
	})

	mw := newGrafanaSessionMiddleware(upstream.URL, "admin", next)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	mw.ServeHTTP(rec, req)

	if proxied {
		t.Fatal("expected redirect before upstream proxy")
	}
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) < 2 {
		t.Fatalf("expected session cookies in response, got %d", len(cookies))
	}
}
