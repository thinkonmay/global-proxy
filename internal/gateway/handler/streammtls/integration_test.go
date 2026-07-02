package streammtls

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/auth"
	"github.com/thinkonmay/global-proxy/api/pkg/audit"
	streammtlscn "github.com/thinkonmay/global-proxy/api/pkg/streammtls"
)

// TestIntegrationHTTPClientIssue exercises the registered /v1/stream/mtls/issue
// route the way the desktop client calls it (external http.Client + JWT + JSON body).
func TestIntegrationHTTPClientIssue(t *testing.T) {
	auth.ConfigureGoTrueAuth(testJWTSecret)

	vaultSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			if payload.CommonName != "desktop:worker-sess-1:vm-abc" {
				t.Errorf("vault common_name = %q", payload.CommonName)
			}
			_, _ = w.Write([]byte(`{"data":{"certificate":` + jsonString(testCertPEM()) + `,"private_key":` + jsonString(testKeyPEM()) + `}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer vaultSrv.Close()

	recorder := audit.NewRecorder("")
	defer recorder.Close()

	mux := http.NewServeMux()
	New(Config{
		VaultURL:      vaultSrv.URL,
		VaultPassword: "secret",
		Recorder:      recorder,
	}).Register(mux)

	gw := httptest.NewServer(mux)
	defer gw.Close()

	const (
		sessionID = "worker-sess-1"
		vmID      = "vm-abc"
	)
	body, _ := json.Marshal(issueRequest{SessionID: sessionID, VMID: vmID})
	req, err := http.NewRequest(http.MethodPost, gw.URL+"/v1/stream/mtls/issue", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testJWT(t, "desktop@example.com"))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, string(raw))
	}

	out, err := ParseIssueResponse(raw)
	if err != nil {
		t.Fatal(err)
	}
	wantCN := streammtlscn.DesktopCN(sessionID, vmID)
	if out.CommonName != wantCN {
		t.Fatalf("common_name=%q want %q", out.CommonName, wantCN)
	}
	if out.SessionID != sessionID || out.VMID != vmID {
		t.Fatalf("ids mismatch: %+v", out)
	}
	if out.CertPEM == "" || out.KeyPEM == "" || out.CAPEM == "" {
		t.Fatalf("missing PEM fields: %+v", out)
	}
	if out.ExpiresAt == "" {
		t.Fatal("missing expires_at")
	}
}

func TestIntegrationHTTPClientRejectsMissingAuth(t *testing.T) {
	auth.ConfigureGoTrueAuth(testJWTSecret)
	mux := http.NewServeMux()
	New(Config{VaultURL: "http://vault", VaultPassword: "secret"}).Register(mux)
	gw := httptest.NewServer(mux)
	defer gw.Close()

	body, _ := json.Marshal(issueRequest{SessionID: "sess-1", VMID: "vm-1"})
	req, err := http.NewRequest(http.MethodPost, gw.URL+"/v1/stream/mtls/issue", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestIntegrationHTTPClientRejectsInvalidIDs(t *testing.T) {
	auth.ConfigureGoTrueAuth(testJWTSecret)
	mux := http.NewServeMux()
	New(Config{VaultURL: "http://vault", VaultPassword: "secret"}).Register(mux)
	gw := httptest.NewServer(mux)
	defer gw.Close()

	body, _ := json.Marshal(issueRequest{SessionID: "bad id", VMID: "vm-1"})
	req, err := http.NewRequest(http.MethodPost, gw.URL+"/v1/stream/mtls/issue", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testJWT(t, "desktop@example.com"))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}
