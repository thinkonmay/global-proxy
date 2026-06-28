package persona

import (
	"context"
	"log/slog"
	"time"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/pkg/usage"
)

// RunBatch executes one persona refresh cycle (used by the worker ticker and tests).
func RunBatch(ctx context.Context, pr *postgrest.Client, usageQ *usage.Querier, cfg Config, log *slog.Logger) error {
	w, err := NewWorker(pr, usageQ, cfg, log)
	if err != nil {
		return err
	}
	w.tick(ctx)
	return nil
}

// StartScheduler starts a persona refresh loop on the global scheduler process.
// Disable APP_PERSONA_ENABLED on the worker container when using this to avoid duplicate work.
func StartScheduler(ctx context.Context, pr *postgrest.Client, usageQ *usage.Querier, cfg Config, every time.Duration, log *slog.Logger) {
	if log == nil {
		log = slog.Default()
	}
	cfg.Every = every
	w, err := NewWorker(pr, usageQ, cfg, log)
	if err != nil {
		log.Error("persona scheduler worker init failed", "err", err)
		return
	}
	go w.Run(ctx)
	log.Info("persona scheduler loop started", "every", every)
}
