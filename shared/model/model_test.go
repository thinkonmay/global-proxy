package model

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Topic names are wire identifiers shared across gateway and worker; a rename
// silently breaks pub/sub routing, so pin them here.
func TestTopicNames(t *testing.T) {
	cases := map[string]string{
		"payment": TopicPayment.Name,
		"sse":     TopicSSE.Name,
		"usage":   TopicUsage.Name,
		"volume":  TopicVolumeJob.Name,
	}
	want := map[string]string{
		"payment": "billing.payment.event",
		"sse":     "sse",
		"usage":   "usage.snapshot",
		"volume":  "jobs.volume",
	}
	for k, got := range cases {
		if got != want[k] {
			t.Errorf("topic %s name = %q, want %q", k, got, want[k])
		}
	}
}

func TestSSETypeConstants(t *testing.T) {
	if SSENotification != "notification" {
		t.Errorf("SSENotification = %q, want notification", SSENotification)
	}
	if SSEPayment != "payment" {
		t.Errorf("SSEPayment = %q, want payment", SSEPayment)
	}
}

// Empty Recipient/Data must drop from the wire (omitempty) so a broadcast and a
// targeted message are distinguishable downstream.
func TestSSEMsgOmitsEmptyFields(t *testing.T) {
	b, err := json.Marshal(SSEMsg{Type: SSENotification})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)
	for _, banned := range []string{"recipient", "data"} {
		if strings.Contains(s, banned) {
			t.Errorf("broadcast SSEMsg must omit %q, got %s", banned, s)
		}
	}
	if !strings.Contains(s, `"type":"notification"`) {
		t.Errorf("SSEMsg missing type, got %s", s)
	}
}

func TestSSEMsgRoundTrip(t *testing.T) {
	in := SSEMsg{
		Type:      SSEPayment,
		Recipient: "user@example.com",
		Data:      json.RawMessage(`{"k":"v"}`),
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out SSEMsg
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Type != in.Type || out.Recipient != in.Recipient {
		t.Errorf("round-trip mismatch: got %+v want %+v", out, in)
	}
	if string(out.Data) != string(in.Data) {
		t.Errorf("Data = %s, want %s", out.Data, in.Data)
	}
}

func TestNotificationRoundTrip(t *testing.T) {
	in := Notification{Title: "hi", Body: "world", Level: "warn"}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out Notification
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out != in {
		t.Errorf("round-trip mismatch: got %+v want %+v", out, in)
	}

	// Level is optional.
	b, _ = json.Marshal(Notification{Title: "t", Body: "b"})
	if strings.Contains(string(b), "level") {
		t.Errorf("empty Level must be omitted, got %s", b)
	}
}

func TestUsageMsgRoundTrip(t *testing.T) {
	ts := time.Date(2026, 6, 24, 10, 0, 0, 0, time.UTC)
	in := UsageMsg{
		EventTime: ts,
		UserEmail: "u@example.com",
		SessionID: "s1",
		Metric:    "session_hours",
		Value:     1.5,
		Cluster:   "c1",
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Optional columns must drop when zero.
	for _, banned := range []string{"node", "volume_id", "tick_bucket", "source"} {
		if strings.Contains(string(b), banned) {
			t.Errorf("zero %q must be omitted, got %s", banned, b)
		}
	}
	var out UsageMsg
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !out.EventTime.Equal(in.EventTime) {
		t.Errorf("EventTime = %v, want %v", out.EventTime, in.EventTime)
	}
	if out.Value != in.Value || out.Metric != in.Metric || out.UserEmail != in.UserEmail {
		t.Errorf("round-trip mismatch: got %+v want %+v", out, in)
	}
}

func TestVolumeJobMsgRoundTrip(t *testing.T) {
	in := VolumeJobMsg{
		RequestID:    "req-1",
		Command:      "create",
		ClusterID:    7,
		Arguments:    json.RawMessage(`{"size":10}`),
		TargetDomain: "node.example.com",
		JobID:        42,
		Email:        "u@example.com",
		VolumeID:     "vol-1",
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out VolumeJobMsg
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.RequestID != in.RequestID || out.Command != in.Command ||
		out.ClusterID != in.ClusterID || out.TargetDomain != in.TargetDomain ||
		out.JobID != in.JobID || out.Email != in.Email || out.VolumeID != in.VolumeID {
		t.Errorf("round-trip mismatch: got %+v want %+v", out, in)
	}
	if string(out.Arguments) != string(in.Arguments) {
		t.Errorf("Arguments = %s, want %s", out.Arguments, in.Arguments)
	}
}

func TestCardRowRoundTrip(t *testing.T) {
	in := CardRow{
		UserID:      99,
		Provider:    "stripe",
		CustomerRef: "cus_1",
		PMRef:       "pm_1",
		Brand:       "visa",
		Last4:       "4242",
		ExpMonth:    12,
		ExpYear:     2030,
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out CardRow
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out != in {
		t.Errorf("round-trip mismatch: got %+v want %+v", out, in)
	}
}
