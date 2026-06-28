package config

func mergePersonaDefaults(cfg *Config) {
	p := &cfg.Persona
	if p.Every == "" {
		p.Every = "1m"
	}
	if p.EnrichMinSpacing == "" {
		p.EnrichMinSpacing = "250ms"
	}
	if p.AppUsageDays <= 0 {
		p.AppUsageDays = 30
	}
}
