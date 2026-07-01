package streammtls

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/auth"
	"github.com/thinkonmay/global-proxy/api/pkg/audit"
)

const testJWTSecret = "stream-mtls-test-secret"

func testJWT(t *testing.T, email string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   "550e8400-e29b-41d4-a716-446655440000",
		"email": email,
		"role":  "authenticated",
		"aud":   "authenticated",
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	s, err := tok.SignedString([]byte(testJWTSecret))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestIssueRequiresAuth(t *testing.T) {
	auth.ConfigureGoTrueAuth(testJWTSecret)
	h := New(Config{VaultURL: "http://vault", VaultPassword: "secret"})
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/stream/mtls/issue", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestIssueSuccessAndAudit(t *testing.T) {
	auth.ConfigureGoTrueAuth(testJWTSecret)

	recorder := audit.NewRecorder("")
	defer recorder.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/auth/userpass/login/"):
			_, _ = w.Write([]byte(`{"auth":{"client_token":"vault-token"}}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/ca/pem"):
			_, _ = w.Write([]byte(testCertPEM()))
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/issue/desktop-client"):
			_, _ = w.Write([]byte(`{"data":{"certificate":` + jsonString(testCertPEM()) + `,"private_key":` + jsonString(testKeyPEM()) + `}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	h := New(Config{
		VaultURL:      srv.URL,
		VaultUsername: "gateway-ops",
		VaultPassword: "secret",
		PKIMount:      "pki",
		PKIRole:       "desktop-client",
		CertTTL:       "2h",
		Recorder:      recorder,
	})
	mux := http.NewServeMux()
	h.Register(mux)

	body, _ := json.Marshal(issueRequest{SessionID: "sess-abc", VMID: "vm-123"})
	req := httptest.NewRequest(http.MethodPost, "/v1/stream/mtls/issue", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testJWT(t, "user@example.com"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	out, err := ParseIssueResponse(rec.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if out.SessionID != "sess-abc" || out.VMID != "vm-123" || out.CertPEM == "" {
		t.Fatalf("out=%+v", out)
	}
	if !strings.HasPrefix(out.CommonName, "desktop:") {
		t.Fatalf("cn=%q", out.CommonName)
	}
}

func TestIssueRejectsMissingIDs(t *testing.T) {
	auth.ConfigureGoTrueAuth(testJWTSecret)
	h := New(Config{VaultURL: "http://vault", VaultPassword: "secret"})
	mux := http.NewServeMux()
	h.Register(mux)

	body, _ := json.Marshal(issueRequest{SessionID: "sess-1"})
	req := httptest.NewRequest(http.MethodPost, "/v1/stream/mtls/issue", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testJWT(t, "user@example.com"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestRegisterSkipsWithoutVaultPassword(t *testing.T) {
	h := New(Config{VaultURL: "http://vault", VaultPassword: ""})
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/stream/mtls/issue", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when handler not registered, got %d", rec.Code)
	}
}

func TestIssueInvalidJSON(t *testing.T) {
	auth.ConfigureGoTrueAuth(testJWTSecret)
	h := New(Config{VaultURL: "http://vault", VaultPassword: "secret"})
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/stream/mtls/issue", strings.NewReader("{"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testJWT(t, "user@example.com"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestIssueRejectsInvalidSessionID(t *testing.T) {
	auth.ConfigureGoTrueAuth(testJWTSecret)
	h := New(Config{VaultURL: "http://vault", VaultPassword: "secret"})
	mux := http.NewServeMux()
	h.Register(mux)

	body, _ := json.Marshal(issueRequest{SessionID: "bad id", VMID: "vm-1"})
	req := httptest.NewRequest(http.MethodPost, "/v1/stream/mtls/issue", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testJWT(t, "user@example.com"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestIssueVaultFailure(t *testing.T) {
	auth.ConfigureGoTrueAuth(testJWTSecret)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "vault down", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	h := New(Config{
		VaultURL:      srv.URL,
		VaultPassword: "secret",
	})
	mux := http.NewServeMux()
	h.Register(mux)

	body, _ := json.Marshal(issueRequest{SessionID: "sess-1", VMID: "vm-1"})
	req := httptest.NewRequest(http.MethodPost, "/v1/stream/mtls/issue", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testJWT(t, "user@example.com"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestIssueUsesDesktopCN(t *testing.T) {
	auth.ConfigureGoTrueAuth(testJWTSecret)

	var issuedCN string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/auth/userpass/login/"):
			_, _ = w.Write([]byte(`{"auth":{"client_token":"vault-token"}}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/ca/pem"):
			_, _ = w.Write([]byte(testCertPEM()))
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/issue/desktop-client"):
			var payload struct {
				CommonName string `json:"common_name"`
			}
			_ = json.NewDecoder(r.Body).Decode(&payload)
			issuedCN = payload.CommonName
			_, _ = w.Write([]byte(`{"data":{"certificate":` + jsonString(testCertPEM()) + `,"private_key":` + jsonString(testKeyPEM()) + `}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	h := New(Config{VaultURL: srv.URL, VaultPassword: "secret"})
	mux := http.NewServeMux()
	h.Register(mux)

	body, _ := json.Marshal(issueRequest{SessionID: "sess-abc", VMID: "vm-123"})
	req := httptest.NewRequest(http.MethodPost, "/v1/stream/mtls/issue", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testJWT(t, "user@example.com"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if issuedCN != "desktop:sess-abc:vm-123" {
		t.Fatalf("issued CN = %q", issuedCN)
	}
}

func TestParseIssueResponseMissingCert(t *testing.T) {
	out, err := ParseIssueResponse([]byte(`{"data":{"session_id":"s","vm_id":"v"}}`))
	if err == nil && out.CertPEM != "" {
		t.Fatal("expected missing cert material")
	}
}

func TestNewDefaults(t *testing.T) {
	h := New(Config{VaultPassword: "secret"})
	if h.cfg.PKIRole != "desktop-client" {
		t.Fatalf("PKIRole = %q", h.cfg.PKIRole)
	}
	if h.cfg.CertTTL != "2h" {
		t.Fatalf("CertTTL = %q", h.cfg.CertTTL)
	}
	if h.cfg.VaultUsername != "gateway-ops" {
		t.Fatalf("VaultUsername = %q", h.cfg.VaultUsername)
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func testCertPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: testCertDER()}))
}

func testKeyPEM() string {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
}

func testCertDER() []byte {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "desktop:sess-abc:vm-123"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(2 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	return der
}
