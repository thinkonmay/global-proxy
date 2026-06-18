package handler

import (
	"context"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	"github.com/thinkonmay/global-proxy/api/shared/model"
	"github.com/thinkonmay/global-proxy/api/shared/repo"
)

type Handler struct {
	repo     *repo.Repo
	eventBus bus.Client
}

func New(r *repo.Repo, eventBus bus.Client) *Handler {
	return &Handler{repo: r, eventBus: eventBus}
}

func (h *Handler) Init() {
	bus.Subscribe(h.eventBus, model.TopicJob, "worker", func(c context.Context, m model.JobMsg) error {
		h.handleJob(c, m)
		return nil
	})
}
