package model

import (
	"context"
	"encoding/json"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
)

// SSEMsg is a fan-out event envelope. Type is the discriminator the client
// switches on; Recipient routes to one user's streams (empty = broadcast); Data
// is the typed payload. Producers build it with a concrete T.
type SSEMsg[T any] struct {
	Type      string `json:"type"`
	Recipient string `json:"recipient,omitempty"`
	Data      T      `json:"data,omitempty"`
}

// SSERaw is the transport form: the payload is left as raw JSON so one topic and
// one hub carry heterogeneous event types, routed by Recipient and discriminated
// by Type at the edge (the hub never decodes Data).
type SSERaw = SSEMsg[json.RawMessage]

// TopicSSE carries SSE events to the gateway, which fans them out by recipient.
var TopicSSE = bus.NewTopic[SSERaw]("sse")

// PublishSSE marshals a typed message into the transport envelope and publishes
// it to TopicSSE — the typed producer entrypoint.
func PublishSSE[T any](ctx context.Context, c bus.Client, msg SSEMsg[T]) error {
	data, err := json.Marshal(msg.Data)
	if err != nil {
		return err
	}
	return bus.Publish(ctx, c, TopicSSE, SSERaw{
		Type:      msg.Type,
		Recipient: msg.Recipient,
		Data:      data,
	})
}
