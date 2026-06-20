package handler

import (
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	"github.com/thinkonmay/global-proxy/api/pkg/idempotency"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

type Handler struct {
	idem     *idempotency.Guard
	eventBus bus.Client
	ch       driver.Conn // ClickHouse, for the usage sink
}

func New(idem *idempotency.Guard, eventBus bus.Client, ch driver.Conn) *Handler {
	return &Handler{idem: idem, eventBus: eventBus, ch: ch}
}

// Init wires every subscription this worker serves.
func (h *Handler) Init() {
	// Jobs
	bus.Subscribe(
		h.eventBus,
		model.TopicJob,
		"worker",
		h.handleJob,
		bus.WithConcurrency(100),
	)

	// Usage events
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
