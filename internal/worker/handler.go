// Package handler composes the worker's per-domain subscribers (volume,
// payment, usage, persona) and exposes a single facade the worker entrypoint
// wires and starts. Each domain owns its own bus subscriptions and lifecycle;
// this package only fans out construction and Init/Start calls.
package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/internal/worker/payment"
	"github.com/thinkonmay/global-proxy/api/internal/worker/persona"
	"github.com/thinkonmay/global-proxy/api/internal/worker/usage"
	"github.com/thinkonmay/global-proxy/api/internal/worker/volume"
	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	"github.com/thinkonmay/global-proxy/api/pkg/idempotency"
	registry "github.com/thinkonmay/global-proxy/api/pkg/payment/registry"
	pb "github.com/thinkonmay/global-proxy/api/pkg/pocketbase"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

type Handler struct {
	eventBus bus.Client
	volume   *volume.Handler
	payment  *payment.Handler
	usage    *usage.Handler
	persona  *persona.Handler
}

func NewHandler(idem *idempotency.Guard, eventBus bus.Client, ch driver.Conn, pr *postgrest.Client, pbc *pb.Client) *Handler {
	return &Handler{
		eventBus: eventBus,
		volume:   volume.New(idem, pr, pbc),
		payment:  payment.New(idem, pr),
		usage:    usage.New(ch, pr, eventBus),
		persona:  persona.New(pr),
	}
}

// Init registers every domain's bus subscriptions.
func (h *Handler) Init() {
	h.volume.Init(h.eventBus)
	h.usage.Init(h.eventBus)
	h.payment.Init(h.eventBus)
}

func (h *Handler) StartUsageCollector(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	return h.usage.StartCollector(ctx, cfg, log)
}

func (h *Handler) StartPersonaWorker(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	return h.persona.Start(ctx, cfg, log)
}

func (h *Handler) StartPaymentPoller(ctx context.Context, reg *registry.Registry, every time.Duration) {
	h.payment.StartPoller(ctx, reg, every)
}
