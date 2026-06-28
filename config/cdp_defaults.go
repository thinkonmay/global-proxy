package config

func mergeCDPDefaults(cfg *Config) {
	etl := &cfg.CDP.FrontendETL
	if etl.Every == "" {
		etl.Every = "6h"
	}
	if etl.Days <= 0 {
		etl.Days = 30
	}
	if cfg.CDP.RybbitClickHouse.Database == "" {
		cfg.CDP.RybbitClickHouse.Database = "analytics"
	}
}
