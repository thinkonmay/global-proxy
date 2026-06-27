package vaultpki

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// CARequest loads the Vault PKI CA used to verify virtdaemon client certificates.
type CARequest struct {
	Addr       string
	Username   string
	Password   string
	PKIMount   string
	GatewayKey string
}

// ClientCAPool returns a cert pool containing the Vault PKI issuing CA.
func ClientCAPool(ctx context.Context, req CARequest) (*x509.CertPool, error) {
	caPEM, err := FetchCAPEM(ctx, req)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("failed to parse Vault CA PEM")
	}
	return pool, nil
}

// FetchCAPEM loads the Vault PKI CA PEM via the gateway Vault proxy.
func FetchCAPEM(ctx context.Context, req CARequest) ([]byte, error) {
	req.Addr = strings.TrimRight(strings.TrimSpace(req.Addr), "/")
	if req.Addr == "" {
		return nil, fmt.Errorf("vault addr required")
	}
	if strings.TrimSpace(req.Password) == "" {
		return nil, fmt.Errorf("vault password required")
	}
	if req.Username == "" {
		req.Username = "virtdaemon"
	}
	if req.PKIMount == "" {
		req.PKIMount = "pki"
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
	token, err := loginUserpass(ctx, client, req.Addr, req.Username, req.Password, req.GatewayKey)
	if err != nil {
		return nil, fmt.Errorf("login: %w", err)
	}
	return fetchCA(ctx, client, req.Addr, token, req.PKIMount, req.GatewayKey)
}
