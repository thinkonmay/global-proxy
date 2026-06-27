package main

import (
	"fmt"
	"log/slog"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/pkg/routingagg"
)

func initRoutingStore(cfg *config.Config) (*routingagg.Store, error) {
	if cfg.Routing.RedisURL == "" {
		return nil, nil
	}
	store, err := routingagg.NewStore(cfg.Routing.RedisURL)
	if err != nil {
		return nil, fmt.Errorf("routing store: %w", err)
	}
	slog.Info("routing store ready", "redis", cfg.Routing.RedisURL)
	return store, nil
}
