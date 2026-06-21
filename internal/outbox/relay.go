package outbox

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

type Row struct {
	ID      int64           `json:"id"`
	Topic   string          `json:"topic"`
	Payload json.RawMessage `json:"payload"`
}

// PollOnce claims unpublished outbox rows via PostgREST, publishes each to NATS,
// then marks published. Failed publish releases the claim for the next poll.
func PollOnce(ctx context.Context, pr *postgrest.Client, eventBus bus.Client, limit int) error {
	var rows []Row
	if err := pr.RPC(ctx, "claim_unpublished_outbox", map[string]any{"p_limit": limit}, &rows); err != nil {
		return err
	}
	for _, row := range rows {
		env := model.VolumeJobEnvelope{
			OutboxID: row.ID,
			Topic:    row.Topic,
			Payload:  ParsePayload(row.Payload),
		}
		topic := model.TopicVolumeJob
		if row.Topic != "" {
			topic = bus.NewTopic[model.VolumeJobEnvelope](row.Topic)
		}
		if err := bus.Publish(ctx, eventBus, topic, env); err != nil {
			if relErr := pr.RPC(ctx, "release_outbox_claim", map[string]any{"p_id": row.ID}, nil); relErr != nil {
				slog.Error("outbox release claim", "id", row.ID, "err", relErr)
			}
			return err
		}
		if err := pr.RPC(ctx, "mark_outbox_published", map[string]any{"p_id": row.ID}, nil); err != nil {
			return err
		}
	}
	return nil
}

func ParsePayload(raw json.RawMessage) model.VolumeJobPayload {
	var p model.VolumeJobPayload
	_ = json.Unmarshal(raw, &p)
	return p
}
