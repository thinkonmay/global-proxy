package contract

import (
	"encoding/json"
	"time"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
)

var TopicJob = bus.NewTopic[JobMsg]("jobs")

type JobMsg struct {
	ID        int64           `json:"id"`
	Command   string          `json:"command"`
	Arguments json.RawMessage `json:"arguments"`
}

// Job mirrors a `job` table row (read by the status endpoint).
type Job struct {
	ID         int64           `json:"id"`
	Command    string          `json:"command"`
	Arguments  json.RawMessage `json:"arguments"`
	Cluster    *int64          `json:"cluster"`
	CreatedAt  time.Time       `json:"created_at"`
	FinishedAt *time.Time      `json:"finished_at"`
	Result     json.RawMessage `json:"result"`
	Success    *bool           `json:"success"`
}
