package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/thinkonmay/global-proxy/api/config"
)

func TestNewConfigLoadsPostgRESTServiceKeyFromEnv(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	const yaml = `
log:
  level: info
  format: text
postgrest:
  url: "http://rest:3000"
nats:
  url: "nats://127.0.0.1:4222"
tls:
  enabled: false
`
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	t.Setenv("APP_POSTGREST_SERVICEKEY", "svc-from-env")
	t.Setenv("APP_POSTGREST_ANONKEY", "anon-from-env")

	cfg, err := config.NewConfig()
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	if cfg.PostgREST.ServiceKey != "svc-from-env" {
		t.Fatalf("ServiceKey=%q want svc-from-env", cfg.PostgREST.ServiceKey)
	}
	if cfg.PostgREST.AnonKey != "anon-from-env" {
		t.Fatalf("AnonKey=%q want anon-from-env", cfg.PostgREST.AnonKey)
	}
}
