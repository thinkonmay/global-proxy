package metricsagg

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequireTheRedMTLS(t *testing.T) {
	called := false
	handler := RequireTheRedMTLS(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusUnauthorized || called {
		t.Fatalf("expected 401 without cert, got %d called=%v", rec.Code, called)
	}

	req = httptest.NewRequest(http.MethodPost, "/", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: "virtdaemon-host"}}},
	}
	rec = httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusForbidden || called {
		t.Fatalf("expected 403 for virtdaemon cert, got %d called=%v", rec.Code, called)
	}

	req = httptest.NewRequest(http.MethodPost, "/", nil)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: TheRedCN("ops@example.com")}}},
	}
	rec = httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusNoContent || !called {
		t.Fatalf("expected 204 for the-red cert, got %d called=%v", rec.Code, called)
	}
}
