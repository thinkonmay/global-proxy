package handler

import (
	"context"
	"log/slog"

	"github.com/thinkonmay/global-proxy/api/shared/model"
)

// handleJob claims + runs + records the job via process. Returns an error to nak
// (redeliver, eventually DLQ); nil to ack.
func (h *Handler) handleJob(ctx context.Context, m model.JobMsg) error {
	return h.process(ctx, m.ID, claimLease, func(ctx context.Context) error {
		slog.Info("handling job", "id", m.ID, "command", m.Command)
		return nil
	})
}
