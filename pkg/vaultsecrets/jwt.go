package vaultsecrets

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// LoadGoTrueJWTSecret reads jwt_secret from Vault KV (secret/data/gotrue) via AppRole.
// Returns ("", nil) when VAULT_GATEWAY_ROLE_ID or VAULT_GATEWAY_SECRET_ID is unset.
func LoadGoTrueJWTSecret(ctx context.Context, vaultAddr string) (string, error) {
	roleID := strings.TrimSpace(os.Getenv("VAULT_GATEWAY_ROLE_ID"))
	secretID := strings.TrimSpace(os.Getenv("VAULT_GATEWAY_SECRET_ID"))
	if roleID == "" || secretID == "" {
		return "", nil
	}
	addr := strings.TrimRight(strings.TrimSpace(vaultAddr), "/")
	if addr == "" {
		return "", fmt.Errorf("vault addr required for AppRole JWT bootstrap")
	}

	client := &http.Client{Timeout: 30 * time.Second}
	token, err := loginAppRole(ctx, client, addr, roleID, secretID)
	if err != nil {
		return "", fmt.Errorf("vault approle login: %w", err)
	}
	secret, err := readKV(ctx, client, addr, token, "secret/data/gotrue", "jwt_secret")
	if err != nil {
		return "", fmt.Errorf("vault read gotrue jwt: %w", err)
	}
	if strings.TrimSpace(secret) == "" {
		return "", fmt.Errorf("vault secret/data/gotrue jwt_secret is empty")
	}
	return secret, nil
}

func loginAppRole(ctx context.Context, client *http.Client, addr, roleID, secretID string) (string, error) {
	body, _ := json.Marshal(map[string]string{
		"role_id":   roleID,
		"secret_id": secretID,
	})
	url := addr + "/v1/auth/approle/login"
	resp, err := doJSON(ctx, client, http.MethodPost, url, "", body)
	if err != nil {
		return "", err
	}
	var out struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(resp, &out); err != nil {
		return "", fmt.Errorf("parse approle login: %w", err)
	}
	if out.Auth.ClientToken == "" {
		return "", fmt.Errorf("approle login returned empty token")
	}
	return out.Auth.ClientToken, nil
}

func readKV(ctx context.Context, client *http.Client, addr, token, path, field string) (string, error) {
	url := fmt.Sprintf("%s/v1/%s", addr, path)
	resp, err := doJSON(ctx, client, http.MethodGet, url, token, nil)
	if err != nil {
		return "", err
	}
	var out struct {
		Data struct {
			Data map[string]string `json:"data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(resp, &out); err != nil {
		return "", fmt.Errorf("parse kv response: %w", err)
	}
	val, ok := out.Data.Data[field]
	if !ok || strings.TrimSpace(val) == "" {
		return "", fmt.Errorf("kv field %q missing in %s", field, path)
	}
	return val, nil
}

func doJSON(ctx context.Context, client *http.Client, method, url, token string, body []byte) ([]byte, error) {
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
