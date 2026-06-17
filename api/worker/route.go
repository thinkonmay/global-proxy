package main

import (
	"context"

	"github.com/thinkonmay/global-proxy/api/contract"
	"github.com/thinkonmay/global-proxy/api/gateway/repo"
	"github.com/thinkonmay/global-proxy/api/pkg/bus"
)

type Handler struct {
	repo     *repo.Repo
	eventBus bus.Client
}

func (h *Handler) Route() {
	bus.Subscribe(h.eventBus, contract.TopicJob, "worker", func(c context.Context, m contract.JobMsg) error {
		h.handleJob(c, m)
		return nil
	})
}
