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
	Upstreams  Upstreams  `mapstructure:"upstreams"`
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
	Meta   string `mapstructure:"meta"`
	Studio string `mapstructure:"studio"`
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
		cfg.TLS.Hosts = strings.Split(hosts, ",")
		for i := range cfg.TLS.Hosts {
			cfg.TLS.Hosts[i] = strings.TrimSpace(cfg.TLS.Hosts[i])
		}
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
	if err := validator.Validate(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
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
