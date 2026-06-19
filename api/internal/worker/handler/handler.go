package handler

import (
	"time"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	"github.com/thinkonmay/global-proxy/api/shared/model"
	"github.com/thinkonmay/global-proxy/api/shared/repo"
)

// claimLease is the lock lease; ~matches the bus AckWait redelivery window.
const claimLease = 30 * time.Second

type Handler struct {
	repo     *repo.Repo
	eventBus bus.Client
}

func New(r *repo.Repo, eventBus bus.Client) *Handler {
	return &Handler{repo: r, eventBus: eventBus}
}

func (h *Handler) Init() {
	bus.Subscribe(h.eventBus, model.TopicJob, "worker", h.handleJob)
}
