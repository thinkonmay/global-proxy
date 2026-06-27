package runtime

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/auth"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/clusterproxy"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/testsupport"
)

func testGoTrueJWT(t *testing.T, secret, userID, email string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   userID,
		"email": email,
		"role":  "authenticated",
		"aud":   "authenticated",
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	s, err := tok.SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRuntimeForwardInfo(t *testing.T) {
	const secret = "test-p2p-secret"
	const jwtSecret = "gotrue-test-secret"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(clusterproxy.InternalHeader) != "1" {
			t.Fatalf("missing internal header")
		}
		if r.Header.Get(clusterproxy.SecretHeader) != secret {
			t.Fatalf("missing secret")
		}
		if r.Header.Get(clusterproxy.UserEmailHeader) != "user@test.net" {
			t.Fatalf("email: %q", r.Header.Get(clusterproxy.UserEmailHeader))
		}
		if r.URL.Path != "/info" {
			t.Fatalf("path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"Hostname": "node1"})
	}))
	defer upstream.Close()

	host := upstream.URL
	auth.ConfigureClusterRegistry(testsupport.TestIssuerRegistry(host, host))
	auth.ConfigureGoTrueAuth(jwtSecret)

	h := New(secret, nil, nil)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/runtime/info?cluster="+url.QueryEscape(host), nil)
	req.Header.Set("Authorization", "Bearer "+testGoTrueJWT(t, jwtSecret, "sub-1", "user@test.net"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRuntimeForwardInfoWithPocketBaseToken(t *testing.T) {
	const secret = "test-p2p-secret"
	const jwtSecret = "gotrue-test-secret"

	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/collections/users/auth-refresh":
			if r.Header.Get("Authorization") != "Bearer legacy-pb-token" {
				t.Fatalf("auth-refresh Authorization = %q", r.Header.Get("Authorization"))
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"token":"refreshed","record":{"email":"pb-user@test.net"}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/info":
			if r.Header.Get(clusterproxy.InternalHeader) != "1" {
				t.Fatalf("missing internal header")
			}
			if r.Header.Get(clusterproxy.SecretHeader) != secret {
				t.Fatalf("missing secret")
			}
			if r.Header.Get(clusterproxy.UserEmailHeader) != "pb-user@test.net" {
				t.Fatalf("email: %q", r.Header.Get(clusterproxy.UserEmailHeader))
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]string{"Hostname": "node1"})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer issuer.Close()

	host := issuer.URL
	auth.ConfigureClusterRegistry(testsupport.TestIssuerRegistry(host, host))
	auth.ConfigureGoTrueAuth(jwtSecret)

	h := New(secret, nil, nil)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/runtime/info?cluster="+url.QueryEscape(host), nil)
	req.Header.Set("Authorization", "Bearer legacy-pb-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRuntimeMissingCluster(t *testing.T) {
	h := New("", nil, nil)
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodGet, "/v1/runtime/info?cluster=", nil)
	req.Header.Set("Authorization", "Bearer test")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}
