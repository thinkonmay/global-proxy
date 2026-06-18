package handler

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/thinkonmay/global-proxy/api/shared/model"
)

func (h *Handler) handleJob(ctx context.Context, m model.JobMsg) {
	slog.Info("handling job", "id", m.ID, "command", m.Command)

	// Mock execution: echo the command back as the result.
	result, _ := json.Marshal(map[string]any{"handled": m.Command})

	if err := h.repo.Complete(ctx, m.ID, result, true); err != nil {
		slog.Error("failed to update job", "id", m.ID, "error", err)
		return
	}
	slog.Info("job finished", "id", m.ID)
}
