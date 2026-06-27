package config

// Routing configures hot cross-cluster VM routing state in Redis (logical DB /2).
type Routing struct {
	RedisURL string `mapstructure:"redisUrl"`
}

func mergeRoutingDefaults(cfg *Config) {
	if cfg.Routing.RedisURL == "" {
		cfg.Routing.RedisURL = "redis://redis:6379/2"
	}
}
