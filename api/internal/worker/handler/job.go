package handler

import (
	"context"
	"errors"
	"log/slog"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	"github.com/thinkonmay/global-proxy/api/pkg/idempotency"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

// dlqJobTopic captures jobs whose failure couldn't be recorded (last resort).
var dlqJobTopic = bus.NewTopic[model.JobMsg](bus.DlqTopic(model.TopicJob.Name))

// runJob is the side-effect (mock for now).
func (h *Handler) runJob(ctx context.Context, m model.JobMsg) error {
	slog.Info("handling job", "id", m.ID, "command", m.Command)
	return nil
}

// handleJob runs the job at most once. A claim error naks for retry; a fn failure
// that can't even be recorded escalates to the DLQ so it isn't silently dropped.
func (h *Handler) handleJob(ctx context.Context, m model.JobMsg) error {
	err := h.idem.Run(ctx, m.ID, func(ctx context.Context) error {
		return h.run(ctx, m)
	})
	if errors.Is(err, idempotency.ErrRecordFailed) {
		if pubErr := bus.Publish(ctx, h.eventBus, dlqJobTopic, m); pubErr != nil {
			// store and DLQ both down: a redelivery would skip, so we can't recover.
			slog.Error("job dropped: store + DLQ unavailable", "id", m.ID, "err", err, "dlqErr", pubErr)
			return nil
		}
		slog.Warn("job escalated to DLQ", "id", m.ID, "err", err)
		return nil
	}
	return err
}
