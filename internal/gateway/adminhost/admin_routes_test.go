package adminhost

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/pkg/admingate"
)

func TestAdminStudioHostSSOOnly(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer mr.Close()

	cfg := &config.Config{
		Admin: config.Admin{
			Enabled:       true,
			AllowedIPs:    []string{"203.0.113.1"},
			AllowedEmails: []string{"ops@thinkmay.net"},
			SigningSecret: "test-secret",
			Redis:         config.Redis{URL: "redis://" + mr.Addr()},
			Hosts: config.AdminHosts{
				Public: "thinkmay.net",
				Studio: "studio.thinkmay.net",
			},
			CookieDomain: ".thinkmay.net",
		},
	}
	studio := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "studio")
	}))
	defer studio.Close()
	cfg.Admin.Upstreams.Studio = studio.URL

	gate, err := InitGate(cfg)
	if err != nil {
		t.Fatal(err)
	}

	token := adminSSOCookie(t, gate)
	public := http.NewServeMux()
	router := admingate.NewHostRouter(cfg.Admin.Hosts.Public, public)
	registerAdminHost(router, cfg.Admin.Hosts.Studio, cfg.Admin.Upstreams.Studio, gate, http.DefaultTransport)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "studio.thinkmay.net"
	req.RemoteAddr = "203.0.113.1:1234"
	req.AddCookie(&http.Cookie{Name: "tm_admin_sso", Value: token})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "studio" {
		t.Fatalf("expected studio proxy after SSO, code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestAdminLitellmHostSSO(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer mr.Close()

	cfg := &config.Config{
		Admin: config.Admin{
			Enabled:          true,
			AllowedIPs:       []string{"203.0.113.1"},
			AllowedEmails:    []string{"ops@thinkmay.net"},
			SigningSecret:    "test-secret",
			LitellmMasterKey: "sk-test-master",
			Redis:            config.Redis{URL: "redis://" + mr.Addr()},
			Hosts: config.AdminHosts{
				Public:  "thinkmay.net",
				Litellm: "litellm.thinkmay.net",
			},
			Upstreams: config.AdminUpstreams{
				Litellm: "", // set below
			},
			CookieDomain: ".thinkmay.net",
		},
	}
	litellm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer sk-test-master" {
			t.Errorf("Authorization = %q, want master key bearer", got)
		}
		_, _ = io.WriteString(w, "litellm")
	}))
	defer litellm.Close()
	cfg.Admin.Upstreams.Litellm = litellm.URL

	gate, err := InitGate(cfg)
	if err != nil {
		t.Fatal(err)
	}

	token := adminSSOCookie(t, gate)
	public := http.NewServeMux()
	router := admingate.NewHostRouter(cfg.Admin.Hosts.Public, public)
	registerLitellmHost(router, cfg, gate)

	req := httptest.NewRequest(http.MethodGet, "/ui", nil)
	req.Host = "litellm.thinkmay.net"
	req.RemoteAddr = "203.0.113.1:1234"
	req.AddCookie(&http.Cookie{Name: "tm_admin_sso", Value: token})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "litellm" {
		t.Fatalf("expected litellm proxy after SSO, code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestAdminStudioHostOptionalBasicAuth(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer mr.Close()

	cfg := &config.Config{
		Admin: config.Admin{
			Enabled:          true,
			BasicAuthEnabled: true,
			AllowedIPs:       []string{"203.0.113.1"},
			AllowedEmails:    []string{"ops@thinkmay.net"},
			SigningSecret:    "test-secret",
			Redis:            config.Redis{URL: "redis://" + mr.Addr()},
			Hosts: config.AdminHosts{
				Public: "thinkmay.net",
				Studio: "studio.thinkmay.net",
			},
			BasicAuthUser: "admin",
			BasicAuthPass: "pass",
			CookieDomain:  ".thinkmay.net",
		},
	}
	studio := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "studio")
	}))
	defer studio.Close()
	cfg.Admin.Upstreams.Studio = studio.URL

	gate, err := InitGate(cfg)
	if err != nil {
		t.Fatal(err)
	}

	token := adminSSOCookie(t, gate)
	public := http.NewServeMux()
	router := admingate.NewHostRouter(cfg.Admin.Hosts.Public, public)
	registerAdminHost(router, cfg.Admin.Hosts.Studio, cfg.Admin.Upstreams.Studio, gate, http.DefaultTransport)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "studio.thinkmay.net"
	req.RemoteAddr = "203.0.113.1:1234"
	req.AddCookie(&http.Cookie{Name: "tm_admin_sso", Value: token})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected basic-auth 401, got %d", rec.Code)
	}

	req.SetBasicAuth("admin", "pass")
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "studio" {
		t.Fatalf("expected studio proxy, code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestGrafanaHostStripsAuthorizationAndSetsProxyUser(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer mr.Close()

	cfg := &config.Config{
		Admin: config.Admin{
			Enabled:       true,
			AllowedIPs:    []string{"203.0.113.1"},
			AllowedEmails: []string{"ops@thinkmay.net"},
			SigningSecret: "test-secret",
			Redis:         config.Redis{URL: "redis://" + mr.Addr()},
			Hosts: config.AdminHosts{
				Public:  "thinkmay.net",
				Grafana: "grafana.thinkmay.net",
			},
			CookieDomain: ".thinkmay.net",
			Upstreams:    config.AdminUpstreams{Grafana: ""},
		},
	}

	var gotAuth, gotProxyUser string
	grafana := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotProxyUser = r.Header.Get(grafanaProxyUserHeader)
		_, _ = io.WriteString(w, "ok")
	}))
	defer grafana.Close()
	cfg.Admin.Upstreams.Grafana = grafana.URL

	gate, err := InitGate(cfg)
	if err != nil {
		t.Fatal(err)
	}
	token := adminSSOCookie(t, gate)

	public := http.NewServeMux()
	router := admingate.NewHostRouter(cfg.Admin.Hosts.Public, public)
	registerGrafanaHost(router, cfg, gate)

	req := httptest.NewRequest(http.MethodGet, "/apis/dashboard.grafana.app/v2/namespaces/default/dashboards", nil)
	req.Host = "grafana.thinkmay.net"
	req.RemoteAddr = "203.0.113.1:1234"
	req.AddCookie(&http.Cookie{Name: "tm_admin_sso", Value: token})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%q", rec.Code, rec.Body.String())
	}
	if gotAuth != "" {
		t.Fatalf("Authorization forwarded to grafana: %q", gotAuth)
	}
	if gotProxyUser != "admin" {
		t.Fatalf("X-WEBAUTH-USER = %q, want admin", gotProxyUser)
	}
}

func adminSSOCookie(t *testing.T, gate *admingate.Gate) string {
	t.Helper()
	mux := http.NewServeMux()
	gate.RegisterRoutes(mux)
	code := "123456"
	if err := gate.SaveOTP(context.Background(), "ops@thinkmay.net", code, time.Minute); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"email": "ops@thinkmay.net", "code": code})
	req := httptest.NewRequest(http.MethodPost, "/admin/otp/verify", bytes.NewReader(body))
	req.RemoteAddr = "203.0.113.1:1234"
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify: %d %s", rec.Code, rec.Body.String())
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "tm_admin_sso" {
			return c.Value
		}
	}
	t.Fatal("missing cookie")
	return ""
}
