package handler

import (
	"context"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	"github.com/thinkonmay/global-proxy/api/pkg/idempotency"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

type Handler struct {
	idem     *idempotency.Guard
	eventBus bus.Client
	ch       driver.Conn
	volumes  *volumeHandler
}

func New(idem *idempotency.Guard, eventBus bus.Client, ch driver.Conn, pr *postgrest.Client) *Handler {
	return &Handler{
		idem:     idem,
		eventBus: eventBus,
		ch:       ch,
		volumes:  newVolumeHandler(idem, pr),
	}
}

func (h *Handler) Init() {
	bus.Subscribe(
		h.eventBus,
		model.TopicVolumeJob,
		"worker-volume",
		func(ctx context.Context, env model.VolumeJobEnvelope) error {
			return h.volumes.handle(ctx, env)
		},
		bus.WithConcurrency(100),
	)

	bus.SubscribeBatch(
		h.eventBus,
		model.TopicUsage,
		"ch-usage-sink",
		h.handleUsage,
		bus.WithBatchSize(5000),
		bus.WithLinger(2*time.Second),
		bus.WithConcurrency(1),
	)
}
