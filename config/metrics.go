package config

// Metrics configures the push ingest → Redis cache → Prometheus scrape aggregator (D16).
type Metrics struct {
	RedisURL           string `mapstructure:"redisUrl"`
	CacheTTLSeconds    int    `mapstructure:"cacheTTLSeconds"`
	ScrapeCacheSeconds int    `mapstructure:"scrapeCacheSeconds"`
	ListenAddr         string `mapstructure:"listenAddr"`
}

func mergeMetricsDefaults(cfg *Config) {
	m := &cfg.Metrics
	if m.RedisURL == "" {
		m.RedisURL = "redis://redis:6379/1"
	}
	if m.CacheTTLSeconds <= 0 {
		m.CacheTTLSeconds = 90
	}
	if m.ListenAddr == "" {
		m.ListenAddr = ":9090"
	}
	if m.ScrapeCacheSeconds <= 0 {
		m.ScrapeCacheSeconds = 10
	}
}
