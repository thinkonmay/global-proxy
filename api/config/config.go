// Package config loads application configuration via viper (env overrides a YAML file).
package config

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/thinkonmay/global-proxy/api/pkg/validator"

	"github.com/spf13/viper"
)

type Config struct {
	Port     string   `mapstructure:"port" validate:"required,numeric"`
	Log      Log      `mapstructure:"log"`
	Postgres Postgres `mapstructure:"postgres"`
	Redis    Redis    `mapstructure:"redis"`
}

type Redis struct {
	Addr string `mapstructure:"addr" validate:"required"` // host:port
}

type Log struct {
	Level     string `mapstructure:"level"  validate:"required,oneof=debug info warn error"`
	Format    string `mapstructure:"format" validate:"required,oneof=json text"`
	AddSource bool   `mapstructure:"addSource"`
}

type Postgres struct {
	URL      string `mapstructure:"url"` // if set, takes precedence over the discrete fields
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	Database string `mapstructure:"database"`
	SSLMode  string `mapstructure:"sslmode"`
}

// DSN returns a pgx-compatible connection string (URL verbatim if provided,
// else a keyword DSN built from the discrete fields; sslmode defaults to disable).
func (p Postgres) DSN() string {
	if p.URL != "" {
		return p.URL
	}
	ssl := p.SSLMode
	if ssl == "" {
		ssl = "disable"
	}
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		p.Host, p.Port, p.Username, p.Password, p.Database, ssl)
}

// NewConfig reads config.yaml (searched in . and ./config), overlays APP_* env
// vars, then validates. Invalid or missing required fields return an error.
func NewConfig() (*Config, error) {
	v := viper.New()
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")
	v.AddConfigPath("./config")

	v.SetEnvPrefix("APP")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		return nil, err
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, err
	}
	if err := validator.Validate(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// SetupLogger sets the process-wide slog.Default from the config. Shared by the
// gateway and worker binaries.
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
