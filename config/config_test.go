package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewConfigFromYAML(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	const yaml = `
log:
  level: debug
  format: json
postgrest:
  url: "http://localhost:3000"
nats:
  url: "nats://127.0.0.1:4222"
relay:
  pollIntervalMs: 250
  batchSize: 10
tls:
  enabled: true
  httpPort: "80"
  httpsPort: "443"
  autocertCache: "/data/.autocert_cache"
  hosts:
    - thinkmay.net
`
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)

	cfg, err := NewConfig()
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	if !cfg.TLS.Enabled || cfg.TLS.HTTPPort != "80" || cfg.TLS.HTTPSPort != "443" {
		t.Fatalf("unexpected tls config: %+v", cfg.TLS)
	}
	if len(cfg.TLS.Hosts) < 1 || cfg.TLS.Hosts[0] != "thinkmay.net" {
		t.Fatalf("hosts: %v", cfg.TLS.Hosts)
	}
	if cfg.RPC.Password1 == "" {
		t.Fatal("expected default rpc password1")
	}
}

func TestNewConfigPlainHTTPDevMode(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	const yaml = `
port: "4000"
log:
  level: info
  format: text
postgrest:
  url: "http://localhost:3000"
nats:
  url: "nats://127.0.0.1:4222"
tls:
  enabled: false
`
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)

	cfg, err := NewConfig()
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	if cfg.Port != "4000" || cfg.TLS.Enabled {
		t.Fatalf("dev config: port=%q tls=%v", cfg.Port, cfg.TLS.Enabled)
	}
}

func TestNewConfigValidationFails(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	const yaml = `
log:
  level: invalid
  format: json
postgrest:
  url: "http://localhost:3000"
nats:
  url: "nats://127.0.0.1:4222"
tls:
  enabled: true
  httpPort: "80"
  httpsPort: "443"
`
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)

	if _, err := NewConfig(); err == nil {
		t.Fatal("expected validation error for invalid log level")
	}
}

func TestStripeWebhookSecretEnv(t *testing.T) {
	t.Setenv("APP_PAYMENT_STRIPE_WEBHOOKSECRET", "whsec_test_123")
	cfg := &Config{}
	mergeEnvSecrets(cfg)
	if cfg.Payment.Stripe.WebhookSecret != "whsec_test_123" {
		t.Fatalf("WebhookSecret = %q, want whsec_test_123", cfg.Payment.Stripe.WebhookSecret)
	}
}
