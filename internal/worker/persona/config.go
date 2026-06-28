package persona

import (
	"fmt"
	"time"

	"github.com/thinkonmay/global-proxy/api/config"
	corepersona "github.com/thinkonmay/global-proxy/api/pkg/persona"
	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	"github.com/thinkonmay/global-proxy/api/pkg/storeindex"
)

// BuildConfig maps gateway config + LiteLLM worker credentials into pkg/persona.Config.
func BuildConfig(cfg *config.Config, eventBus bus.Client) (corepersona.Config, error) {
	pc := cfg.Persona
	every, err := time.ParseDuration(pc.Every)
	if err != nil {
		return corepersona.Config{}, fmt.Errorf("persona.every: %w", err)
	}
	spacing, err := time.ParseDuration(pc.EnrichMinSpacing)
	if err != nil {
		return corepersona.Config{}, fmt.Errorf("persona.enrichMinSpacing: %w", err)
	}
	days := pc.AppUsageDays
	if days <= 0 {
		days = 30
	}
	return corepersona.Config{
		Every:            every,
		MaxBatch:         pc.MaxBatch,
		Concurrent:       pc.Concurrent,
		EnrichMinSpacing: spacing,
		AppUsageDays:     days,
		StoreIndex:       storeindex.NewClient(cfg.Logs.ElasticsearchURL, ""),
		Bus:              eventBus,
		LLM: corepersona.LLMConfig{
			BaseURL: cfg.LLM.BaseURL,
			APIKey:  cfg.LLM.APIKey,
			Model:   cfg.LLM.Model,
		},
	}, nil
}
