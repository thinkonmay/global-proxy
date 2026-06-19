package handler

import (
	"context"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	"github.com/thinkonmay/global-proxy/api/pkg/idempotency"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

type Handler struct {
	idem     *idempotency.Guard
	eventBus bus.Client
	run      func(ctx context.Context, m model.JobMsg) error // side-effect (overridable in tests)
}

func New(idem *idempotency.Guard, eventBus bus.Client) *Handler {
	h := &Handler{idem: idem, eventBus: eventBus}
	h.run = h.runJob
	return h
}

func (h *Handler) Init() {
	bus.Subscribe(h.eventBus, model.TopicJob, "worker", h.handleJob)
}
