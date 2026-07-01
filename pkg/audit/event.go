package audit

import "time"

// Event is a structured gateway/admin audit record (C5 / OC2).
// No JWT, secrets, or OTP codes — only correlation and action metadata.
type Event struct {
	Timestamp  string `json:"@timestamp"`
	RequestID  string `json:"request_id,omitempty"`
	UserEmail  string `json:"user_email,omitempty"`
	Route      string `json:"route"`
	Method     string `json:"method,omitempty"`
	Action     string `json:"action"`
	Status     int    `json:"status,omitempty"`
	RemoteIP   string `json:"remote_ip,omitempty"`
	Host       string `json:"host,omitempty"`
	UserAgent  string `json:"user_agent,omitempty"`
	Component  string `json:"component"` // gateway, admin, auth_proxy
	Detail     string `json:"detail,omitempty"`
}

func newEvent(action, component string) Event {
	return Event{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Action:    action,
		Component: component,
	}
}
