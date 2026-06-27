// Package config loads application configuration via viper (env overrides a YAML
// file). Shared by the gateway and worker binaries — one config, no per-binary
// variants. No direct-DB credentials: all global data is reached over PostgREST.
package config

import (
	"log/slog"
	"os"
	"strings"

	"github.com/thinkonmay/global-proxy/api/pkg/validator"

	"github.com/spf13/viper"
)

type Config struct {
	Port           string         `mapstructure:"port"`
	Log            Log            `mapstructure:"log"`
	PostgREST      PostgREST      `mapstructure:"postgrest"`
	PocketBase     PocketBase     `mapstructure:"pocketbase"`
	Supabase       Supabase       `mapstructure:"supabase"`
	Upstreams      Upstreams      `mapstructure:"upstreams"`
	Admin          Admin          `mapstructure:"admin"`
	WAF            WAF            `mapstructure:"waf"`
	Nats           Nats           `mapstructure:"nats"`
	ClickHouse     ClickHouse     `mapstructure:"clickhouse"`
	RPC            RPC            `mapstructure:"rpc"`
	Scheduler      Scheduler      `mapstructure:"scheduler"`
	Metrics        Metrics        `mapstructure:"metrics"`
	UsageCollector UsageCollector `mapstructure:"usageCollector"`
	Persona        Persona        `mapstructure:"persona"`
	Payment        Payment        `mapstructure:"payment"`
	Gateway        Gateway        `mapstructure:"gateway"`
	Runtime        Runtime        `mapstructure:"runtime"`
	Storj          Storj          `mapstructure:"storj"`
	LLM            LLM            `mapstructure:"llm"`
	TLS            TLS            `mapstructure:"tls"`
}

// Scheduler replaces global pg_cron (D15/P14): periodic PostgREST RPC ticks.
// Postgres keeps the billing SQL (P5); the worker only triggers it on a timer.
type Scheduler struct {
	Enabled bool           `mapstructure:"enabled"`
	Jobs    []SchedulerJob `mapstructure:"jobs"`
}

// SchedulerJob is one timer-driven PostgREST RPC. Every is a Go duration string
// (e.g. "30s", "1m"); RPC is the Postgres function name (POST /rpc/<rpc>); Args
// is the optional JSON arg object (nil/empty = no-arg RPC); TimeoutMs bounds the
// per-tick call (0 = scheduler default).
type SchedulerJob struct {
	Name      string         `mapstructure:"name"`
	Every     string         `mapstructure:"every"`
	RPC       string         `mapstructure:"rpc"`
	Args      map[string]any `mapstructure:"args"`
	TimeoutMs int            `mapstructure:"timeoutMs"`
}

// UsageCollector replaces legacy snapshoot_v6 / globalproxy pulls (F06 / P1-B).
type UsageCollector struct {
	Enabled        bool   `mapstructure:"enabled"`
	Every          string `mapstructure:"every"`
	AddonEvery     string `mapstructure:"addonEvery"`
	SessionMinutes int    `mapstructure:"sessionMinutes"`
}

// Persona configures the global CDP interim worker (P1-C).
type Persona struct {
	Enabled          bool   `mapstructure:"enabled"`
	Every            string `mapstructure:"every"`
	MaxBatch         int    `mapstructure:"maxBatch"`
	Concurrent       int    `mapstructure:"concurrent"`
	RybbitMinSpacing string `mapstructure:"rybbitMinSpacing"`
	RybbitURL        string `mapstructure:"rybbitURL"`
	RybbitAPIKey     string `mapstructure:"rybbitAPIKey"`
	RybbitSiteDomain string `mapstructure:"rybbitSiteDomain"`
}

// Payment configures provider checkout + status polling in the worker (G8).
// Replaces Postgres get_*_data, on_transaction_driver_v2, and verify_all_transactions_v2 HTTP.
// Provider credentials are loaded from .env via APP_PAYMENT_* (not config.yaml).
type Payment struct {
	Enabled   bool   `mapstructure:"enabled"`
	PollEvery string `mapstructure:"pollEvery"`
	Stripe struct {
		SecretKey     string `mapstructure:"secretKey"`
		WebhookSecret string `mapstructure:"webhookSecret"`
	} `mapstructure:"stripe"`
	PayOS struct {
		ClientID     string `mapstructure:"clientId"`
		ClientSecret string `mapstructure:"clientSecret"`
		ChecksumKey  string `mapstructure:"checksumKey"`
	} `mapstructure:"payos"`
	PayerMax struct {
		AppID      string `mapstructure:"appId"`
		MerchantNo string `mapstructure:"merchantNo"`
		BaseURL    string `mapstructure:"baseURL"`
		PrivateKey string `mapstructure:"privateKey"`
		PublicKey  string `mapstructure:"publicKey"`
	} `mapstructure:"payermax"`
}

type TLS struct {
	Enabled       bool     `mapstructure:"enabled"`
	HTTPPort      string   `mapstructure:"httpPort" validate:"omitempty,numeric"`
	HTTPSPort     string   `mapstructure:"httpsPort" validate:"omitempty,numeric"`
	AutocertCache string   `mapstructure:"autocertCache"`
	Hosts         []string `mapstructure:"hosts"`
}

type Gateway struct {
	PublicURL string `mapstructure:"publicURL"`
}

// Runtime configures gateway→cluster runtime (Track C3).
type Runtime struct {
	// ClusterSecret is deprecated — runtime uses virtdaemon gRPC only (Track C3).
	ClusterSecret string `mapstructure:"clusterSecret"`
	// Grpc enables mTLS virtdaemon gRPC for GET /v1/runtime/info (D25/D26).
	Grpc RuntimeGrpc `mapstructure:"grpc"`
}

// RuntimeGrpc configures gateway→cluster-master persistent.Daemon gRPC.
type RuntimeGrpc struct {
	Enabled        bool   `mapstructure:"enabled"`
	Port           int    `mapstructure:"port"`
	ClientCN       string `mapstructure:"clientCN"`
	PKIMount       string `mapstructure:"pkiMount"`
	PKIRole        string `mapstructure:"pkiRole"`
	HomeIssuerHost string `mapstructure:"homeIssuerHost"`
	HomeOverride   string `mapstructure:"homeOverride"`
	VaultPassword  string `mapstructure:"vaultPassword"`
}

// Storj configures the global uplink access grant for user bucket file APIs.
type Storj struct {
	AccessGrant string `mapstructure:"accessGrant"`
}

type RPC struct {
	Password1 string `mapstructure:"password1"`
}

// Upstreams are the non-PostgREST targets the gateway reverse-proxies.
type Upstreams struct {
	Meta    string `mapstructure:"meta"`
	Studio  string `mapstructure:"studio"`
	Storage string `mapstructure:"storage"`
	Website string `mapstructure:"website"`
	Kong    string `mapstructure:"kong"`   // internal Supabase edge (D21) — auth proxy target
	GoTrue  string `mapstructure:"gotrue"` // deprecated alias for kong; must not point at auth:9999
	Vault   string `mapstructure:"vault"`  // internal HashiCorp Vault (D27) — PKI proxy target
}

// Supabase holds Kong consumer keys and Studio basic-auth credentials.
type Supabase struct {
	AnonKey           string `mapstructure:"anonKey"`
	PublishableKey    string `mapstructure:"publishableKey"`
	ServiceKey        string `mapstructure:"serviceKey"`
	SecretKey         string `mapstructure:"secretKey"`
	JWTSecret         string `mapstructure:"jwtSecret"` // GoTrue HS256 signing key (Track C1)
	DashboardUser     string `mapstructure:"dashboardUser"`
	DashboardPassword string `mapstructure:"dashboardPassword"`
}

// WAF restricts public catalog read paths to allowed IPs (globalproxy parity).
type WAF struct {
	Coraza          Coraza   `mapstructure:"coraza"`
	AllowedIPs      []string `mapstructure:"allowedIPs"`
	PublicReadPaths []string `mapstructure:"publicReadPaths"`
}

// Coraza configures OWASP Coraza WAF (ModSecurity-compatible) at the edge.
type Coraza struct {
	Enabled          bool     `mapstructure:"enabled"`
	OWASPCRS         bool     `mapstructure:"owaspCRS"`
	RequestBodyLimit int      `mapstructure:"requestBodyLimit"`
	SkipPaths        []string `mapstructure:"skipPaths"`
}

type ClickHouse struct {
	Addr     string `mapstructure:"addr"`
	Database string `mapstructure:"database"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

type PostgREST struct {
	URL        string `mapstructure:"url" validate:"required,url"`
	AnonKey    string `mapstructure:"anonKey"`
	ServiceKey string `mapstructure:"serviceKey"`
}

// PocketBase holds cluster PocketBase superuser credentials for gateway-side
// admin API calls (auth-with-password once, bearer token reuse).
type PocketBase struct {
	URL        string `mapstructure:"url" validate:"omitempty,url"`
	IssuerHost string `mapstructure:"issuerHost" validate:"omitempty"`
	Username   string `mapstructure:"username"`
	Password   string `mapstructure:"password"`
}

type Nats struct {
	URL      string `mapstructure:"url" validate:"required"`
	Optional bool   `mapstructure:"optional"`
}

type Log struct {
	Level     string `mapstructure:"level"  validate:"required,oneof=debug info warn error"`
	Format    string `mapstructure:"format" validate:"required,oneof=json text"`
	AddSource bool   `mapstructure:"addSource"`
}

func NewConfig() (*Config, error) {
	v := viper.New()
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")
	v.AddConfigPath("./config")
	v.AddConfigPath("/config")

	v.SetEnvPrefix("APP")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	v.SetDefault("rpc.password1", "thinkmay protect your data")
	v.SetDefault("nats.url", "nats://nats:4222")
	v.SetDefault("clickhouse.database", "platform")
	v.SetDefault("tls.enabled", true)
	v.SetDefault("tls.httpPort", "80")
	v.SetDefault("tls.httpsPort", "443")
	v.SetDefault("tls.autocertCache", ".autocert_cache")
	v.SetDefault("waf.coraza.enabled", true)
	v.SetDefault("waf.coraza.owaspCRS", true)
	v.SetDefault("waf.coraza.requestBodyLimit", 10485760)
	v.SetDefault("admin.enabled", false)
	v.SetDefault("admin.basicAuthEnabled", false)
	v.SetDefault("scheduler.enabled", false)
	v.SetDefault("metrics.cacheTTLSeconds", 90)
	v.SetDefault("usageCollector.enabled", true)
	v.SetDefault("usageCollector.every", "5m")
	v.SetDefault("usageCollector.addonEvery", "1h")
	v.SetDefault("usageCollector.sessionMinutes", 5)
	v.SetDefault("persona.enabled", false)
	v.SetDefault("persona.every", "1m")
	v.SetDefault("persona.maxBatch", 20)
	v.SetDefault("persona.concurrent", 10)
	v.SetDefault("persona.rybbitMinSpacing", "250ms")
	v.SetDefault("payment.enabled", false)
	v.SetDefault("payment.pollEvery", "5m")
	v.SetDefault("metrics.scrapeCacheSeconds", 10)
	v.SetDefault("metrics.redisUrl", "redis://redis:6379/1")
	v.SetDefault("metrics.listenAddr", ":9090")

	if err := v.ReadInConfig(); err != nil {
		return nil, err
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, err
	}
	if cfg.RPC.Password1 == "" {
		cfg.RPC.Password1 = "thinkmay protect your data"
	}
	if hosts := os.Getenv("APP_TLS_HOSTS"); hosts != "" {
		cfg.TLS.Hosts = splitCommaTrim(hosts)
	}
	if ips := os.Getenv("APP_WAF_ALLOWEDIPS"); ips != "" {
		cfg.WAF.AllowedIPs = splitCommaTrim(ips)
	}
	if ips := os.Getenv("APP_ADMIN_ALLOWEDIPS"); ips != "" {
		cfg.Admin.AllowedIPs = splitCommaTrim(ips)
	}
	if emails := os.Getenv("APP_ADMIN_ALLOWEDEMAILS"); emails != "" {
		cfg.Admin.AllowedEmails = splitCommaTrim(emails)
	}
	if cfg.TLS.Enabled {
		if cfg.TLS.HTTPPort == "" {
			cfg.TLS.HTTPPort = "80"
		}
		if cfg.TLS.HTTPSPort == "" {
			cfg.TLS.HTTPSPort = "443"
		}
		if cfg.TLS.AutocertCache == "" {
			cfg.TLS.AutocertCache = ".autocert_cache"
		}
	} else if cfg.Port == "" {
		cfg.Port = "4000"
	}
	mergeEnvSecrets(&cfg)
	mergeSupabaseKeys(&cfg)
	mergeAdminDefaults(&cfg)
	mergeMetricsDefaults(&cfg)
	mergeLLMDefaults(&cfg)
	if err := validator.Validate(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func mergeSupabaseKeys(cfg *Config) {
	if cfg.Supabase.AnonKey == "" {
		cfg.Supabase.AnonKey = cfg.PostgREST.AnonKey
	}
	if cfg.Supabase.ServiceKey == "" {
		cfg.Supabase.ServiceKey = cfg.PostgREST.ServiceKey
	}
	if len(cfg.WAF.PublicReadPaths) == 0 {
		cfg.WAF.PublicReadPaths = defaultPublicReadPaths()
	}
	mergeCorazaDefaults(&cfg.WAF.Coraza)
	mergeUpstreamDefaults(&cfg.Upstreams)
}

func mergeUpstreamDefaults(u *Upstreams) {
	if u.Kong == "" {
		u.Kong = strings.TrimSpace(u.GoTrue)
	}
	if u.GoTrue == "" {
		u.GoTrue = strings.TrimSpace(u.Kong)
	}
}

func defaultCorazaSkipPaths() []string {
	return []string{
		"/auth/v1/",
		"/storage/v1/",
		"/vault/v1/",
		"/v1/metrics/push",
		"/api/track",
		"/api/identify",
		"/api/script.js",
		"/api/site/tracking-config/",
		"/api/session-replay/",
	}
}

func mergeCorazaSkipPaths(existing, defaults []string) []string {
	seen := make(map[string]struct{}, len(existing)+len(defaults))
	out := make([]string, 0, len(existing)+len(defaults))
	for _, paths := range [][]string{existing, defaults} {
		for _, p := range paths {
			if p == "" {
				continue
			}
			if _, ok := seen[p]; ok {
				continue
			}
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	return out
}

func mergeCorazaDefaults(c *Coraza) {
	if c.RequestBodyLimit <= 0 {
		c.RequestBodyLimit = 10 << 20
	}
	c.SkipPaths = mergeCorazaSkipPaths(c.SkipPaths, defaultCorazaSkipPaths())
}

func splitCommaTrim(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (c *Config) SetupLogger() {
	var level slog.Level
	switch c.Log.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level:     level,
		AddSource: c.Log.AddSource,
	})))
}
