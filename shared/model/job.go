package model

import (
	"encoding/json"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
)

var TopicJob = bus.NewTopic[JobMsg]("jobs")

// JobMsg is a job published to the bus. ID is the idempotency key (set by the
// gateway at publish time).
type JobMsg struct {
	ID        string          `json:"id"`
	Command   string          `json:"command"`
	Arguments json.RawMessage `json:"arguments"`
}
