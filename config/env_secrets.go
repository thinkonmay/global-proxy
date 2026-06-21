package config

import "os"

// mergeEnvSecrets overlays compose-provided APP_* env vars onto cfg.
// Viper AutomaticEnv does not populate nested keys during Unmarshal; secrets
// live in .env only (not config.yaml) and must be read explicitly.
func mergeEnvSecrets(cfg *Config) {
	setEnvString(&cfg.PostgREST.AnonKey, "APP_POSTGREST_ANONKEY")
	setEnvString(&cfg.PostgREST.ServiceKey, "APP_POSTGREST_SERVICEKEY")
	setEnvString(&cfg.Supabase.AnonKey, "APP_SUPABASE_ANONKEY")
	setEnvString(&cfg.Supabase.ServiceKey, "APP_SUPABASE_SERVICEKEY")
	setEnvString(&cfg.Supabase.DashboardUser, "APP_SUPABASE_DASHBOARDUSER")
	setEnvString(&cfg.Supabase.DashboardPassword, "APP_SUPABASE_DASHBOARDPASSWORD")
	setEnvString(&cfg.Admin.SigningSecret, "APP_ADMIN_SIGNINGSECRET")
	setEnvString(&cfg.Admin.Resend.APIKey, "APP_ADMIN_RESEND_APIKEY")
	setEnvString(&cfg.PocketBase.URL, "APP_POCKETBASE_URL")
	setEnvString(&cfg.PocketBase.Username, "APP_POCKETBASE_USERNAME")
	setEnvString(&cfg.PocketBase.Password, "APP_POCKETBASE_PASSWORD")
	setEnvString(&cfg.LLM.BaseURL, "APP_LLM_BASEURL")
	setEnvString(&cfg.LLM.APIKey, "APP_LLM_APIKEY")
	setEnvString(&cfg.Storj.AccessGrant, "APP_STORJ_ACCESSGRANT")
	setEnvString(&cfg.Metrics.IngestSecret, "APP_METRICS_INGESTSECRET")
	setEnvString(&cfg.ClickHouse.Password, "APP_CLICKHOUSE_PASSWORD")
	setEnvString(&cfg.Persona.RybbitAPIKey, "APP_PERSONA_RYBBITAPIKEY")
	setEnvString(&cfg.Payment.Stripe.SecretKey, "APP_PAYMENT_STRIPE_SECRETKEY")
	setEnvString(&cfg.Payment.PayOS.ClientID, "APP_PAYMENT_PAYOS_CLIENTID")
	setEnvString(&cfg.Payment.PayOS.ClientSecret, "APP_PAYMENT_PAYOS_CLIENTSECRET")
	setEnvString(&cfg.Payment.PayOS.ChecksumKey, "APP_PAYMENT_PAYOS_CHECKSUMKEY")
	setEnvString(&cfg.Payment.PayerMax.AppID, "APP_PAYMENT_PAYERMAX_APPID")
	setEnvString(&cfg.Payment.PayerMax.MerchantNo, "APP_PAYMENT_PAYERMAX_MERCHANTNO")
	setEnvString(&cfg.Payment.PayerMax.BaseURL, "APP_PAYMENT_PAYERMAX_BASEURL")
	setEnvString(&cfg.Payment.PayerMax.PrivateKey, "APP_PAYMENT_PAYERMAX_PRIVATEKEY")
	setEnvString(&cfg.Payment.PayerMax.PublicKey, "APP_PAYMENT_PAYERMAX_PUBLICKEY")
	setEnvString(&cfg.Payment.Payssion.APIKey, "APP_PAYMENT_PAYSSION_APIKEY")
	setEnvString(&cfg.Payment.Payssion.PMID, "APP_PAYMENT_PAYSSION_PMID")
	setEnvString(&cfg.Payment.Payssion.SecretKey, "APP_PAYMENT_PAYSSION_SECRETKEY")
	setEnvString(&cfg.Payment.Payssion.Link, "APP_PAYMENT_PAYSSION_LINK")
}

func setEnvString(dst *string, key string) {
	if v := os.Getenv(key); v != "" {
		*dst = v
	}
}
