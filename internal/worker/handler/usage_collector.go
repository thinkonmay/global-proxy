package handler

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/pkg/metricsagg"
	"github.com/thinkonmay/global-proxy/api/pkg/usage"
)

// StartUsageCollector runs the F06 metering tick loop in-process when enabled.
// It reads WorkerInfor from the metrics Redis cache, updates Postgres billing
// counters, and publishes usage.snapshot events (consumed by this worker's CH sink).
func (h *Handler) StartUsageCollector(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	uc := cfg.UsageCollector
	if !uc.Enabled {
		return nil
	}
	if log == nil {
		log = slog.Default()
	}

	every, err := time.ParseDuration(uc.Every)
	if err != nil {
		return fmt.Errorf("usageCollector.every: %w", err)
	}
	addonEvery, err := time.ParseDuration(uc.AddonEvery)
	if err != nil {
		return fmt.Errorf("usageCollector.addonEvery: %w", err)
	}

	cache, err := metricsagg.NewCacheWithOptions(metricsagg.CacheOptions{
		RedisURL:           cfg.Metrics.RedisURL,
		NodeTTLSeconds:     cfg.Metrics.CacheTTLSeconds,
		ScrapeCacheSeconds: cfg.Metrics.ScrapeCacheSeconds,
	})
	if err != nil {
		return fmt.Errorf("metrics cache: %w", err)
	}

	dedup, err := usage.NewDedup(cfg.Metrics.RedisURL)
	if err != nil {
		_ = cache.Close()
		return fmt.Errorf("usage dedup: %w", err)
	}

	collector := usage.NewCollector(
		cache,
		usage.NewCatalog(h.pr, every),
		dedup,
		h.pr,
		h.eventBus,
		log,
		usage.Options{
			ShadowMode:    uc.ShadowMode,
			TickInterval:  every,
			AddonInterval: addonEvery,
			SessionMins:   uc.SessionMinutes,
		},
	)

	go func() {
		defer func() { _ = cache.Close() }()
		defer func() { _ = dedup.Close() }()
		collector.Run(ctx)
	}()

	log.Info("usage collector started in worker",
		"session_every", every,
		"addon_every", addonEvery,
		"shadow", uc.ShadowMode,
		"session_minutes", uc.SessionMinutes,
	)
	return nil
}
