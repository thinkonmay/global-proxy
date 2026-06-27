// Package certmanager wraps golang.org/x/crypto/acme/autocert for Let's Encrypt TLS.
// B10: internal cert manager — same .autocert_cache pattern as globalproxy/PocketBase.
package certmanager

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// Config holds autocert cache directory and allowed hostnames.
type Config struct {
	CacheDir string
	Hosts    []string
}

// Manager issues and caches TLS certificates via ACME HTTP-01.
type Manager struct {
	acme *autocert.Manager
}

// New builds a cert manager. At least one host is required.
func New(cfg Config) (*Manager, error) {
	if len(cfg.Hosts) == 0 {
		return nil, fmt.Errorf("certmanager: at least one host required")
	}
	cacheDir := cfg.CacheDir
	if cacheDir == "" {
		cacheDir = ".autocert_cache"
	}
	return &Manager{
		acme: &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache(cacheDir),
			HostPolicy: autocert.HostWhitelist(cfg.Hosts...),
		},
	}, nil
}

// TLSConfig returns a tls.Config suitable for HTTPS servers (:443).
func (m *Manager) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: m.acme.GetCertificate,
		NextProtos:     []string{acme.ALPNProto, "h2", "http/1.1"},
	}
}

// TLSConfigWithClientAuth returns TLS config that accepts optional virtdaemon client certs.
func (m *Manager) TLSConfigWithClientAuth(clientCAs *x509.CertPool) *tls.Config {
	cfg := m.TLSConfig()
	if clientCAs != nil {
		cfg.ClientCAs = clientCAs
		cfg.ClientAuth = tls.VerifyClientCertIfGiven
	}
	return cfg
}

// HTTPChallengeHandler serves ACME HTTP-01 challenges on :80 and redirects other traffic to next.
func (m *Manager) HTTPChallengeHandler(next http.Handler) http.Handler {
	return m.acme.HTTPHandler(next)
}
