package persona

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/thinkonmay/global-proxy/api/config"
	corepersona "github.com/thinkonmay/global-proxy/api/pkg/persona"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/pkg/usage"
)

type Handler struct {
	pr *postgrest.Client
}

func New(pr *postgrest.Client) *Handler {
	return &Handler{pr: pr}
}

func (h *Handler) Start(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	pc := cfg.Persona
	if !pc.Enabled || pc.ScheduleOnScheduler {
		return nil
	}
	if log == nil {
		log = slog.Default()
	}
	usageQ, err := openUsageQuerier(cfg)
	if err != nil {
		return err
	}
	pcfg, err := BuildConfig(cfg)
	if err != nil {
		return err
	}
	pcfg.Usage = usageQ
	worker, err := corepersona.NewWorker(h.pr, usageQ, pcfg, log)
	if err != nil {
		return err
	}
	go worker.Run(ctx)
	log.Info("persona worker started", "every", pcfg.Every)
	return nil
}

// StartSchedulerLoop runs persona refresh on the scheduler process (LiteLLM worker key).
func StartSchedulerLoop(ctx context.Context, cfg *config.Config, pr *postgrest.Client, log *slog.Logger) error {
	pc := cfg.Persona
	if !pc.Enabled || !pc.ScheduleOnScheduler {
		return nil
	}
	if log == nil {
		log = slog.Default()
	}
	usageQ, err := openUsageQuerier(cfg)
	if err != nil {
		return err
	}
	pcfg, err := BuildConfig(cfg)
	if err != nil {
		return err
	}
	pcfg.Usage = usageQ
	corepersona.StartScheduler(ctx, pr, usageQ, pcfg, pcfg.Every, log)
	return nil
}

func openUsageQuerier(cfg *config.Config) (*usage.Querier, error) {
	chConn, err := usage.OpenCH(cfg.ClickHouse)
	if err != nil {
		return nil, fmt.Errorf("persona clickhouse: %w", err)
	}
	return usage.NewQuerier(chConn), nil
}
