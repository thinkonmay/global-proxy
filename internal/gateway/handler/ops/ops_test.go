package ops

import (
	"bytes"
	"context"
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

	"github.com/alicebob/miniredis/v2"
	"github.com/thinkonmay/global-proxy/api/pkg/admingate"
)

func testGate(t *testing.T) *admingate.Gate {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mr.Close)
	store, err := admingate.NewRedisOTPStore("redis://" + mr.Addr())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	gate, err := admingate.NewGate(admingate.Config{
		AllowedEmails:   []string{"ops@thinkmay.net"},
		SigningSecret:   "unit-test-secret",
		SessionTTLHours: 8,
		OTPTTLMinutes:   10,
	}, store, store, admingate.LogMailer{})
	if err != nil {
		t.Fatal(err)
	}
	return gate
}

func ssoToken(t *testing.T, gate *admingate.Gate) string {
	t.Helper()
	const code = "123456"
	if err := gate.SaveOTP(context.Background(), "ops@thinkmay.net", code, time.Minute); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	gate.RegisterPublicAccessRoutes(mux)
	body, _ := json.Marshal(map[string]string{"email": "ops@thinkmay.net", "code": code})
	req := httptest.NewRequest(http.MethodPost, "/admin/access/otp/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify failed: %d %s", rec.Code, rec.Body.String())
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "tm_admin_sso" {
			return c.Value
		}
	}
	t.Fatal("missing tm_admin_sso cookie")
	return ""
}

func TestIssueMTLSRequiresSSO(t *testing.T) {
	h := New(Config{Gate: testGate(t)})
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/ops/mtls/issue", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestIssueMTLSSuccess(t *testing.T) {
	gate := testGate(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/auth/userpass/login/"):
			_, _ = w.Write([]byte(`{"auth":{"client_token":"vault-token"}}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/ca/pem"):
			_, _ = w.Write([]byte(testCertPEM()))
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/issue/the-red"):
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
		PKIRole:       "the-red",
		CertTTL:       "8h",
		Gate:          gate,
	})
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodPost, "/v1/ops/mtls/issue", nil)
	req.Header.Set("Authorization", "Bearer "+ssoToken(t, gate))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	out, err := ParseIssueResponse(rec.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if out.Email != "ops@thinkmay.net" || out.CertPEM == "" || out.KeyPEM == "" {
		t.Fatalf("out=%+v", out)
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
		Subject:      pkix.Name{CommonName: "the-red:ops_at_thinkmay.net"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(8 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	return der
}
