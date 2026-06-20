package handler

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/pkg/persona"
	"github.com/thinkonmay/global-proxy/api/pkg/pocketbase"
)

func (h *Handler) StartPersonaWorker(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	pc := cfg.Persona
	if !pc.Enabled {
		return nil
	}
	if log == nil {
		log = slog.Default()
	}
	every, err := time.ParseDuration(pc.Every)
	if err != nil {
		return fmt.Errorf("persona.every: %w", err)
	}
	spacing, err := time.ParseDuration(pc.RybbitMinSpacing)
	if err != nil {
		return fmt.Errorf("persona.rybbitMinSpacing: %w", err)
	}

	pb := pocketbase.New(pocketbase.Config{
		URL:      cfg.PocketBase.URL,
		Username: cfg.PocketBase.Username,
		Password: cfg.PocketBase.Password,
	})

	worker, err := persona.NewWorker(h.pr, pb, persona.Config{
		Every:            every,
		MaxBatch:         pc.MaxBatch,
		Concurrent:       pc.Concurrent,
		RybbitMinSpacing: spacing,
		Rybbit: persona.RybbitConfig{
			URL:        pc.RybbitURL,
			APIKey:     pc.RybbitAPIKey,
			SiteDomain: pc.RybbitSiteDomain,
		},
		LLM: persona.LLMConfig{
			BaseURL: cfg.LLM.BaseURL,
			APIKey:  cfg.LLM.APIKey,
			Model:   cfg.LLM.Model,
		},
	}, log)
	if err != nil {
		return err
	}

	go worker.Run(ctx)
	log.Info("persona worker started in gateway worker", "every", every)
	return nil
}
