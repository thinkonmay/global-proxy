package vaultpki

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

// Material holds PEM-encoded TLS assets issued by Vault PKI.
type Material struct {
	CertPEM   []byte
	KeyPEM    []byte
	CACertPEM []byte
}

func (m *Material) keyPair() (tls.Certificate, error) {
	if m == nil {
		return tls.Certificate{}, fmt.Errorf("nil mTLS material")
	}
	return tls.X509KeyPair(m.CertPEM, m.KeyPEM)
}

func (m *Material) caPool() (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(m.CACertPEM) {
		return nil, fmt.Errorf("failed to parse Vault CA PEM")
	}
	return pool, nil
}

// ServerTLS returns a config for virtdaemon gRPC server (requires client certs).
func (m *Material) ServerTLS() (*tls.Config, error) {
	cert, err := m.keyPair()
	if err != nil {
		return nil, err
	}
	pool, err := m.caPool()
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}, nil
}

// ClientTLS returns a config for virtdaemon gRPC client (verifies server + presents client cert).
func (m *Material) ClientTLS() (*tls.Config, error) {
	cert, err := m.keyPair()
	if err != nil {
		return nil, err
	}
	pool, err := m.caPool()
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
	}, nil
}
