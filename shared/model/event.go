package model

import (
	"context"
	"encoding/json"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
)

// EventRaw is a server-push event on the bus. Domain selects the
// /v1/event/{domain} stream it belongs to; Recipient routes to one user's
// streams (empty = broadcast to the domain); Data is the JSON payload written
// verbatim to the client. The hub never decodes Data.
type EventRaw struct {
	Domain    string          `json:"domain,omitempty"`
	Recipient string          `json:"recipient,omitempty"`
	Data      json.RawMessage `json:"data,omitempty"`
}

// TopicEvent carries push events to the gateway, which fans each one out to the
// matching domain stream of its recipient.
var TopicEvent = bus.NewTopic[EventRaw]("event")

// PublishEvent marshals data and publishes it to TopicEvent for one domain and
// recipient — the producer entrypoint.
func PublishEvent[T any](ctx context.Context, c bus.Client, domain, recipient string, data T) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return bus.Publish(ctx, c, TopicEvent, EventRaw{
		Domain:    domain,
		Recipient: recipient,
		Data:      b,
	})
}
