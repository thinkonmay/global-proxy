package config

import (
	"os"
	"strconv"
)

// mergeEnvSecrets overlays compose-provided APP_* env vars onto cfg.
// Viper AutomaticEnv does not populate nested keys during Unmarshal; secrets
// live in .env only (not config.yaml) and must be read explicitly.
func mergeEnvSecrets(cfg *Config) {
	setEnvString(&cfg.PostgREST.AnonKey, "APP_POSTGREST_ANONKEY")
	setEnvString(&cfg.PostgREST.ServiceKey, "APP_POSTGREST_SERVICEKEY")
	setEnvString(&cfg.Supabase.AnonKey, "APP_SUPABASE_ANONKEY")
	setEnvString(&cfg.Supabase.ServiceKey, "APP_SUPABASE_SERVICEKEY")
	setEnvString(&cfg.Supabase.JWTSecret, "APP_SUPABASE_JWTSECRET")
	setEnvString(&cfg.Supabase.DashboardUser, "APP_SUPABASE_DASHBOARDUSER")
	setEnvString(&cfg.Supabase.DashboardPassword, "APP_SUPABASE_DASHBOARDPASSWORD")
	setEnvString(&cfg.Admin.SigningSecret, "APP_ADMIN_SIGNINGSECRET")
	setEnvString(&cfg.Admin.Resend.APIKey, "APP_ADMIN_RESEND_APIKEY")
	setEnvString(&cfg.Admin.Resend.From, "APP_ADMIN_RESEND_FROM")
	setEnvString(&cfg.Admin.LitellmMasterKey, "APP_LITELLM_MASTERKEY")
	setEnvString(&cfg.Runtime.Grpc.HomeIssuerHost, "CLUSTER_HOME_DOMAIN")
	if cfg.Runtime.Grpc.HomeIssuerHost == "" {
		setEnvString(&cfg.Runtime.Grpc.HomeIssuerHost, "GATEWAY_PUBLIC_HOST")
	}
	setEnvString(&cfg.LLM.BaseURL, "APP_LLM_BASEURL")
	setEnvString(&cfg.LLM.APIKey, "APP_LLM_APIKEY")
	setEnvString(&cfg.LLM.Model, "APP_LLM_MODEL")
	setEnvString(&cfg.Storj.AccessGrant, "APP_STORJ_ACCESSGRANT")
	setEnvString(&cfg.Runtime.Grpc.VaultPassword, "VAULT_VIRTDAEMON_PASSWORD")
	setEnvString(&cfg.Runtime.Grpc.HomeOverride, "APP_RUNTIME_GRPC_HOME")
	setEnvString(&cfg.Runtime.Grpc.HomeServerName, "APP_RUNTIME_GRPC_SERVERNAME")
	setEnvString(&cfg.ClickHouse.Addr, "APP_CLICKHOUSE_ADDR")
	setEnvString(&cfg.ClickHouse.Database, "APP_CLICKHOUSE_DATABASE")
	setEnvString(&cfg.ClickHouse.Username, "APP_CLICKHOUSE_USERNAME")
	setEnvString(&cfg.ClickHouse.Password, "APP_CLICKHOUSE_PASSWORD")
	setEnvString(&cfg.CDP.RybbitClickHouse.Addr, "APP_RYBBIT_CLICKHOUSE_ADDR")
	setEnvString(&cfg.CDP.RybbitClickHouse.Database, "APP_RYBBIT_CLICKHOUSE_DATABASE")
	setEnvString(&cfg.CDP.RybbitClickHouse.Username, "APP_RYBBIT_CLICKHOUSE_USERNAME")
	setEnvString(&cfg.CDP.RybbitClickHouse.Password, "APP_RYBBIT_CLICKHOUSE_PASSWORD")
	setEnvInt(&cfg.CDP.RybbitSiteID, "APP_CDP_RYBBIT_SITE_ID")
	setEnvBool(&cfg.CDP.FrontendETL.Enabled, "APP_CDP_FRONTEND_ETL_ENABLED")
	setEnvString(&cfg.CDP.FrontendETL.Every, "APP_CDP_FRONTEND_ETL_EVERY")
	setEnvInt(&cfg.CDP.FrontendETL.Days, "APP_CDP_FRONTEND_ETL_DAYS")
	setEnvString(&cfg.Payment.Stripe.SecretKey, "APP_PAYMENT_STRIPE_SECRETKEY")
	setEnvString(&cfg.Payment.Stripe.WebhookSecret, "APP_PAYMENT_STRIPE_WEBHOOKSECRET")
	setEnvString(&cfg.Payment.PayOS.ClientID, "APP_PAYMENT_PAYOS_CLIENTID")
	setEnvString(&cfg.Payment.PayOS.ClientSecret, "APP_PAYMENT_PAYOS_CLIENTSECRET")
	setEnvString(&cfg.Payment.PayOS.ChecksumKey, "APP_PAYMENT_PAYOS_CHECKSUMKEY")
	setEnvString(&cfg.Payment.PayerMax.AppID, "APP_PAYMENT_PAYERMAX_APPID")
	setEnvString(&cfg.Payment.PayerMax.MerchantNo, "APP_PAYMENT_PAYERMAX_MERCHANTNO")
	setEnvString(&cfg.Payment.PayerMax.BaseURL, "APP_PAYMENT_PAYERMAX_BASEURL")
	setEnvString(&cfg.Payment.PayerMax.PrivateKey, "APP_PAYMENT_PAYERMAX_PRIVATEKEY")
	setEnvString(&cfg.Payment.PayerMax.PublicKey, "APP_PAYMENT_PAYERMAX_PUBLICKEY")
	setEnvString(&cfg.Mail.APIKey, "APP_MAIL_RESEND_APIKEY")
	setEnvString(&cfg.Mail.From, "APP_MAIL_RESEND_FROM")
	setEnvString(&cfg.Upstreams.Meta, "APP_UPSTREAMS_META")
	setEnvString(&cfg.Upstreams.Studio, "APP_UPSTREAMS_STUDIO")
	setEnvString(&cfg.Upstreams.Storage, "APP_UPSTREAMS_STORAGE")
	setEnvString(&cfg.Upstreams.Website, "APP_UPSTREAMS_WEBSITE")
	setEnvString(&cfg.Upstreams.Kong, "APP_UPSTREAMS_KONG")
	setEnvString(&cfg.Upstreams.GoTrue, "APP_UPSTREAMS_GOTRUE")
	setEnvString(&cfg.Upstreams.Vault, "APP_UPSTREAMS_VAULT")
}

func setEnvString(dst *string, key string) {
	if v := os.Getenv(key); v != "" {
		*dst = v
	}
}

func setEnvInt(dst *int, key string) {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			*dst = n
		}
	}
}

func setEnvBool(dst *bool, key string) {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			*dst = b
		}
	}
}
