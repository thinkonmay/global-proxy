package main

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

func TestAdminStudioHostRequiresBasicAuthAfterSSO(t *testing.T) {
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

	gate, err := initAdminGate(cfg)
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
