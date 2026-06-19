package model

import (
	"encoding/json"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
)

// TopicSSE carries server-sent events to the gateway, which fans them out to
// connected clients.
var TopicSSE = bus.NewTopic[SSEMsg]("sse")

// SSEType tags the kind of event so clients can switch on it. Add a const here
// (and a payload type below) for each new kind.
type SSEType string

const (
	SSENotification SSEType = "notification"
)

// SSEMsg is one event on the bus. Recipient routes it to a single user's
// streams; empty broadcasts to everyone. Data is the type-specific payload.
type SSEMsg struct {
	Type      SSEType         `json:"type"`
	Recipient string          `json:"recipient,omitempty"`
	Data      json.RawMessage `json:"data,omitempty"`
}

// Notification is the payload for SSENotification.
type Notification struct {
	Title string `json:"title"`
	Body  string `json:"body"`
	Level string `json:"level,omitempty"` // info | warn | error
}
