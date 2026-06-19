package handler

import (
	"context"
	"log/slog"

	"github.com/thinkonmay/global-proxy/api/shared/model"
)

// handleJob runs the job at most once via the idempotency guard: a duplicate
// skips (nil -> ack); the first delivery runs the side-effect and records the
// outcome. A claim (register) error propagates so the bus redelivers for retry;
// everything else acks (a crash or recorded failure just loses the message).
func (h *Handler) handleJob(ctx context.Context, m model.JobMsg) error {
	return h.idem.Run(ctx, m.ID, func(ctx context.Context) error {
		slog.Info("handling job", "id", m.ID, "command", m.Command)
		return nil
	})
}
