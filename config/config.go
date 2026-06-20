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
	Port       string     `mapstructure:"port"`
	Log        Log        `mapstructure:"log"`
	PostgREST  PostgREST  `mapstructure:"postgrest"`
	Supabase   Supabase   `mapstructure:"supabase"`
	Upstreams  Upstreams  `mapstructure:"upstreams"`
	WAF        WAF        `mapstructure:"waf"`
	Nats       Nats       `mapstructure:"nats"`
	ClickHouse ClickHouse `mapstructure:"clickhouse"`
	RPC        RPC        `mapstructure:"rpc"`
	Relay      Relay      `mapstructure:"relay"`
	Gateway    Gateway    `mapstructure:"gateway"`
	TLS        TLS        `mapstructure:"tls"`
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

type RPC struct {
	Password1 string `mapstructure:"password1"`
}

type Relay struct {
	PollIntervalMs int `mapstructure:"pollIntervalMs"`
	BatchSize      int `mapstructure:"batchSize"`
}

// Upstreams are the non-PostgREST targets the gateway reverse-proxies.
type Upstreams struct {
	Meta    string `mapstructure:"meta"`
	Studio  string `mapstructure:"studio"`
	Storage string `mapstructure:"storage"`
}

// Supabase holds Kong consumer keys and Studio basic-auth credentials.
type Supabase struct {
	AnonKey           string `mapstructure:"anonKey"`
	PublishableKey    string `mapstructure:"publishableKey"`
	ServiceKey        string `mapstructure:"serviceKey"`
	SecretKey         string `mapstructure:"secretKey"`
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
	v.SetDefault("relay.pollIntervalMs", 500)
	v.SetDefault("relay.batchSize", 50)
	v.SetDefault("clickhouse.database", "platform")
	v.SetDefault("tls.enabled", true)
	v.SetDefault("tls.httpPort", "80")
	v.SetDefault("tls.httpsPort", "443")
	v.SetDefault("tls.autocertCache", ".autocert_cache")
	v.SetDefault("waf.coraza.enabled", true)
	v.SetDefault("waf.coraza.owaspCRS", true)
	v.SetDefault("waf.coraza.requestBodyLimit", 10485760)

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
	if cfg.Relay.PollIntervalMs < 1 {
		cfg.Relay.PollIntervalMs = 500
	}
	if cfg.Relay.BatchSize < 1 {
		cfg.Relay.BatchSize = 50
	}
	if hosts := os.Getenv("APP_TLS_HOSTS"); hosts != "" {
		cfg.TLS.Hosts = splitCommaTrim(hosts)
	}
	if ips := os.Getenv("APP_WAF_ALLOWEDIPS"); ips != "" {
		cfg.WAF.AllowedIPs = splitCommaTrim(ips)
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
	mergeSupabaseKeys(&cfg)
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
}

func mergeCorazaDefaults(c *Coraza) {
	if c.RequestBodyLimit <= 0 {
		c.RequestBodyLimit = 10 << 20
	}
	if len(c.SkipPaths) == 0 {
		c.SkipPaths = []string{"/storage/v1/"}
	}
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
