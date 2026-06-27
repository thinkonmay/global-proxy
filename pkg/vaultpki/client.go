package vaultpki

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// IssueRequest identifies the daemon certificate to request from Vault PKI.
type IssueRequest struct {
	Addr       string
	Username   string
	Password   string
	PKIMount   string
	PKIRole    string
	TTL        string
	CommonName string
	IPSANs     []string
	SkipVerify bool
	GatewayKey string
}

// Issue logs into Vault (userpass) and requests a PKI certificate.
func Issue(ctx context.Context, req IssueRequest) (*Material, error) {
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
	if req.PKIRole == "" {
		req.PKIRole = "virtdaemon"
	}
	if req.TTL == "" {
		req.TTL = "24h"
	}
	if req.CommonName == "" {
		host, err := os.Hostname()
		if err != nil || host == "" {
			return nil, fmt.Errorf("common_name required and hostname unavailable")
		}
		req.CommonName = host
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS12,
				InsecureSkipVerify: req.SkipVerify,
			},
		},
	}

	token, err := loginUserpass(ctx, client, req.Addr, req.Username, req.Password, req.GatewayKey)
	if err != nil {
		return nil, fmt.Errorf("login: %w", err)
	}
	caPEM, err := fetchCA(ctx, client, req.Addr, token, req.PKIMount, req.GatewayKey)
	if err != nil {
		return nil, fmt.Errorf("fetch CA: %w", err)
	}
	certPEM, keyPEM, err := issueCert(ctx, client, req.Addr, token, req, req.GatewayKey)
	if err != nil {
		return nil, fmt.Errorf("issue cert: %w", err)
	}
	return &Material{
		CertPEM:   certPEM,
		KeyPEM:    keyPEM,
		CACertPEM: caPEM,
	}, nil
}

func loginUserpass(ctx context.Context, client *http.Client, addr, user, password, gatewayKey string) (string, error) {
	body, _ := json.Marshal(map[string]string{"password": password})
	url := fmt.Sprintf("%s/v1/auth/userpass/login/%s", addr, user)
	resp, err := doJSON(ctx, client, http.MethodPost, url, "", body, gatewayKey)
	if err != nil {
		return "", fmt.Errorf("vault login: %w", err)
	}
	var out struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(resp, &out); err != nil {
		return "", fmt.Errorf("parse login response: %w", err)
	}
	if out.Auth.ClientToken == "" {
		return "", fmt.Errorf("vault login returned empty token")
	}
	return out.Auth.ClientToken, nil
}

// pemFromResponse extracts a PEM block from a Vault /ca/pem body (raw PEM or JSON-wrapped).
func pemFromResponse(raw []byte) ([]byte, bool) {
	s := strings.TrimSpace(strings.TrimPrefix(string(raw), "\ufeff"))
	if idx := strings.Index(s, "-----BEGIN"); idx >= 0 {
		return []byte(strings.TrimSpace(s[idx:])), true
	}
	return nil, false
}

func fetchCA(ctx context.Context, client *http.Client, addr, token, mount, gatewayKey string) ([]byte, error) {
	url := fmt.Sprintf("%s/v1/%s/ca/pem", addr, mount)
	resp, err := doJSON(ctx, client, http.MethodGet, url, token, nil, gatewayKey)
	if err != nil {
		return nil, fmt.Errorf("vault ca: %w", err)
	}
	if pem, ok := pemFromResponse(resp); ok {
		return pem, nil
	}
	var nested struct {
		Data struct {
			Certificate string `json:"certificate"`
		} `json:"data"`
	}
	if err := json.Unmarshal(resp, &nested); err == nil && strings.TrimSpace(nested.Data.Certificate) != "" {
		return []byte(nested.Data.Certificate), nil
	}
	var flat struct {
		Data string `json:"data"`
	}
	if err := json.Unmarshal(resp, &flat); err != nil {
		return nil, fmt.Errorf("vault ca pem: %w", err)
	}
	if strings.TrimSpace(flat.Data) == "" {
		return nil, fmt.Errorf("vault ca pem empty")
	}
	return []byte(flat.Data), nil
}

func issueCert(ctx context.Context, client *http.Client, addr, token string, req IssueRequest, gatewayKey string) ([]byte, []byte, error) {
	payload := map[string]string{
		"common_name": req.CommonName,
		"ttl":         req.TTL,
	}
	if len(req.IPSANs) > 0 {
		payload["ip_sans"] = strings.Join(req.IPSANs, ",")
	}
	body, _ := json.Marshal(payload)
	url := fmt.Sprintf("%s/v1/%s/issue/%s", addr, req.PKIMount, req.PKIRole)
	resp, err := doJSON(ctx, client, http.MethodPost, url, token, body, gatewayKey)
	if err != nil {
		return nil, nil, fmt.Errorf("vault issue: %w", err)
	}
	var out struct {
		Data struct {
			Certificate string `json:"certificate"`
			PrivateKey  string `json:"private_key"`
		} `json:"data"`
	}
	if err := json.Unmarshal(resp, &out); err != nil {
		return nil, nil, fmt.Errorf("parse issue response: %w", err)
	}
	if out.Data.Certificate == "" || out.Data.PrivateKey == "" {
		return nil, nil, fmt.Errorf("vault issue returned empty cert or key")
	}
	return []byte(out.Data.Certificate), []byte(out.Data.PrivateKey), nil
}

func doJSON(ctx context.Context, client *http.Client, method, url, token string, body []byte, gatewayKey string) ([]byte, error) {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, r)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	if key := strings.TrimSpace(gatewayKey); key != "" {
		req.Header.Set("apikey", key)
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return raw, nil
}
