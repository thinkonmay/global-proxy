package model

import (
	"encoding/json"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
)

var TopicMailJob = bus.NewTopic[MailJobMsg]("jobs.mail")

// MailJobMsg is a product/in-app mail job on the bus. The gateway (or any
// trusted publisher) sends the thin payload; the worker is the sole DB writer —
// it inserts the ledger row (dedup on RequestID), optionally sends via Resend,
// and patches status.
type MailJobMsg struct {
	RequestID string `json:"request_id"`
	Email     string `json:"email"`
	Title     string `json:"title"`
	Subject   string `json:"subject"`
	FinalHTML string `json:"final_html"`
	TextBody  string `json:"text_body,omitempty"`
	SendEmail bool   `json:"send_email"`
	InApp     bool   `json:"in_app"`
	CTA       json.RawMessage `json:"cta,omitempty"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`

	// Filled by the worker (not on the wire from the gateway).
	MailID int64 `json:"mail_id"`
}
