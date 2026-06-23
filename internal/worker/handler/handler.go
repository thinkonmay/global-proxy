package handler

import (
	"context"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	"github.com/thinkonmay/global-proxy/api/pkg/idempotency"
	"github.com/thinkonmay/global-proxy/api/pkg/pocketbase"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

type Handler struct {
	idem        *idempotency.Guard
	eventBus    bus.Client
	ch          driver.Conn
	pr          *postgrest.Client
	volumes     *volumeHandler
	settleRPC   func(ctx context.Context, fn string, args map[string]any) error
	listPending func(ctx context.Context) ([]pendingTxn, error)
	saveCard    func(ctx context.Context, ev model.PaymentEvent) error
}

func New(idem *idempotency.Guard, eventBus bus.Client, ch driver.Conn, pr *postgrest.Client, pb *pocketbase.Client) *Handler {
	h := &Handler{
		idem:     idem,
		eventBus: eventBus,
		ch:       ch,
		pr:       pr,
		volumes:  newVolumeHandler(idem, pr, pb),
	}
	h.settleRPC = func(ctx context.Context, fn string, args map[string]any) error {
		return pr.RPC(ctx, fn, args, nil)
	}
	h.saveCard = func(ctx context.Context, ev model.PaymentEvent) error {
		return h.persistCard(ctx, ev)
	}
	return h
}

func (h *Handler) Init() {
	bus.Subscribe(
		h.eventBus,
		model.TopicVolumeJob,
		"worker-volume",
		func(ctx context.Context, env model.VolumeJobEnvelope) error {
			return h.volumes.handle(ctx, env)
		},
		bus.WithConcurrency(16),
		bus.WithMaxDeliver(5),
	)

	bus.SubscribeBatch(
		h.eventBus,
		model.TopicUsage,
		"ch-usage-sink",
		h.handleUsage,
		bus.WithBatchSize(5000),
		bus.WithLinger(2*time.Second),
		bus.WithConcurrency(1),
		bus.WithDeliverNew(),
		bus.WithoutDLQ(),
	)

	bus.Subscribe(
		h.eventBus,
		model.TopicPaymentEvent,
		"payment-settle",
		h.handlePaymentEvent,
		bus.WithConcurrency(8),
		bus.WithMaxDeliver(5),
	)
}
