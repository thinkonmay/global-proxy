package vaultpki

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sync"
	"time"
)

const (
	renewalFraction = 0.8
	minRenewLead    = 5 * time.Minute
	reissueRetry    = 5 * time.Minute
)

// Reloadable holds hot-swappable mTLS material for gRPC server and client credentials.
type Reloadable struct {
	mu      sync.RWMutex
	current *Material
}

func NewReloadable() *Reloadable {
	return &Reloadable{}
}

// Store replaces the active certificate material.
func (r *Reloadable) Store(m *Material) error {
	if m == nil {
		return fmt.Errorf("nil mTLS material")
	}
	if _, err := m.Leaf(); err != nil {
		return err
	}
	r.mu.Lock()
	r.current = m.clone()
	r.mu.Unlock()
	return nil
}

// Material returns a clone of the active material.
func (r *Reloadable) Material() *Material {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.current == nil {
		return nil
	}
	return r.current.clone()
}

func (m *Material) clone() *Material {
	if m == nil {
		return nil
	}
	out := *m
	out.CertPEM = append([]byte(nil), m.CertPEM...)
	out.KeyPEM = append([]byte(nil), m.KeyPEM...)
	out.CACertPEM = append([]byte(nil), m.CACertPEM...)
	return &out
}

// Leaf parses the active leaf certificate.
func (m *Material) Leaf() (*x509.Certificate, error) {
	if m == nil {
		return nil, fmt.Errorf("nil mTLS material")
	}
	block, _ := pem.Decode(m.CertPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

// RenewalDelay returns how long to wait before re-issuing (80% of cert lifetime).
func RenewalDelay(m *Material) (time.Duration, error) {
	if m == nil {
		return 0, fmt.Errorf("nil mTLS material")
	}
	leaf, err := m.Leaf()
	if err != nil {
		return 0, err
	}
	lifetime := leaf.NotAfter.Sub(leaf.NotBefore)
	if lifetime <= 0 {
		return minRenewLead, nil
	}
	renewAt := leaf.NotBefore.Add(time.Duration(float64(lifetime) * renewalFraction))
	delay := time.Until(renewAt)
	if delay < minRenewLead {
		delay = minRenewLead
	}
	return delay, nil
}

// ReissueRetryDelay is the backoff after a failed Vault re-issue attempt.
func ReissueRetryDelay() time.Duration {
	return reissueRetry
}

type certSnapshot struct {
	cert tls.Certificate
	pool *x509.CertPool
}

func (r *Reloadable) snapshot() (certSnapshot, error) {
	r.mu.RLock()
	m := r.current
	r.mu.RUnlock()
	if m == nil {
		return certSnapshot{}, fmt.Errorf("no mTLS material loaded")
	}
	cert, err := m.keyPair()
	if err != nil {
		return certSnapshot{}, err
	}
	pool, err := m.caPool()
	if err != nil {
		return certSnapshot{}, err
	}
	return certSnapshot{cert: cert, pool: pool}, nil
}

// ServerTLSConfig returns a tls.Config whose certificate is read on each new TLS handshake.
// Existing connections are not torn down when material is swapped.
func (r *Reloadable) ServerTLSConfig() (*tls.Config, error) {
	if _, err := r.snapshot(); err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			snap, err := r.snapshot()
			if err != nil {
				return nil, err
			}
			return &tls.Config{
				MinVersion:   tls.VersionTLS12,
				Certificates: []tls.Certificate{snap.cert},
				ClientCAs:    snap.pool,
				ClientAuth:   tls.RequireAndVerifyClientCert,
			}, nil
		},
	}, nil
}

// ClientTLSConfig returns a tls.Config whose client certificate is read on each new handshake.
func (r *Reloadable) ClientTLSConfig() (*tls.Config, error) {
	if _, err := r.snapshot(); err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			snap, err := r.snapshot()
			if err != nil {
				return nil, err
			}
			c := snap.cert
			return &c, nil
		},
		RootCAs: func() *x509.CertPool {
			snap, err := r.snapshot()
			if err != nil {
				return nil
			}
			return snap.pool
		}(),
	}, nil
}
