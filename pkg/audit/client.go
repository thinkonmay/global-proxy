package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	defaultBulkTimeout = 5 * time.Second
	defaultQueueSize   = 256
)

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9._\-+/=]{20,}`),
	regexp.MustCompile(`(?i)eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`),
	regexp.MustCompile(`(?i)"code"\s*:\s*"\d{6}"`),
}

// Client bulk-indexes audit events into Elasticsearch audit-logs-{yyyy.MM.dd}.
type Client struct {
	esURL string
	http  *http.Client
}

func NewClient(esURL string) *Client {
	return &Client{
		esURL: strings.TrimRight(strings.TrimSpace(esURL), "/"),
		http:  &http.Client{Timeout: defaultBulkTimeout},
	}
}

func (c *Client) Enabled() bool {
	return c != nil && c.esURL != ""
}

func (c *Client) index(ctx context.Context, ev Event) {
	if !c.Enabled() {
		slog.Info("audit",
			"action", ev.Action,
			"component", ev.Component,
			"route", ev.Route,
			"request_id", ev.RequestID,
			"user_email", ev.UserEmail,
			"status", ev.Status,
		)
		return
	}
	redactEvent(&ev)
	ts := time.Now().UTC()
	if ev.Timestamp != "" {
		if t, err := time.Parse(time.RFC3339Nano, ev.Timestamp); err == nil {
			ts = t.UTC()
		} else if t, err := time.Parse(time.RFC3339, ev.Timestamp); err == nil {
			ts = t.UTC()
		}
	}
	index := fmt.Sprintf("audit-logs-%s", ts.Format("2006.01.02"))
	body, err := json.Marshal(ev)
	if err != nil {
		return
	}
	action := fmt.Sprintf(`{"index":{"_index":"%s"}}`, index)
	payload := action + "\n" + string(body) + "\n"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.esURL+"/_bulk", strings.NewReader(payload))
	if err != nil {
		slog.Warn("audit index request", "err", err)
		return
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	resp, err := c.http.Do(req)
	if err != nil {
		slog.Warn("audit elasticsearch", "err", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		slog.Warn("audit elasticsearch status", "status", resp.StatusCode, "body", strings.TrimSpace(string(b)))
	}
}

func redactEvent(ev *Event) {
	ev.Detail = redactSecrets(ev.Detail)
	ev.UserAgent = redactSecrets(ev.UserAgent)
}

func redactSecrets(s string) string {
	out := s
	for _, re := range secretPatterns {
		out = re.ReplaceAllString(out, "[REDACTED]")
	}
	return out
}

// Recorder emits audit events asynchronously; failures never block callers (C5).
type Recorder struct {
	client *Client
	ch     chan Event
	once   sync.Once
}

func NewRecorder(esURL string) *Recorder {
	c := NewClient(esURL)
	r := &Recorder{
		client: c,
		ch:     make(chan Event, defaultQueueSize),
	}
	go r.drain()
	return r
}

func (r *Recorder) drain() {
	for ev := range r.ch {
		ctx, cancel := context.WithTimeout(context.Background(), defaultBulkTimeout)
		r.client.index(ctx, ev)
		cancel()
	}
}

// Record enqueues one audit event (non-blocking).
func (r *Recorder) Record(ev Event) {
	if r == nil {
		return
	}
	select {
	case r.ch <- ev:
	default:
		slog.Warn("audit queue full, dropping event", "action", ev.Action, "route", ev.Route)
	}
}

// Close stops the background drainer.
func (r *Recorder) Close() {
	if r == nil {
		return
	}
	r.once.Do(func() { close(r.ch) })
}

// RecordEvents bulk-indexes events synchronously (tests).
func (c *Client) RecordEvents(ctx context.Context, events []Event) error {
	if !c.Enabled() {
		return nil
	}
	var bulk bytes.Buffer
	for _, ev := range events {
		redactEvent(&ev)
		ts := time.Now().UTC()
		if ev.Timestamp != "" {
			if t, err := time.Parse(time.RFC3339Nano, ev.Timestamp); err == nil {
				ts = t.UTC()
			}
		}
		index := fmt.Sprintf("audit-logs-%s", ts.Format("2006.01.02"))
		action := fmt.Sprintf(`{"index":{"_index":"%s"}}`, index)
		body, err := json.Marshal(ev)
		if err != nil {
			continue
		}
		bulk.WriteString(action)
		bulk.WriteByte('\n')
		bulk.Write(body)
		bulk.WriteByte('\n')
	}
	if bulk.Len() == 0 {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.esURL+"/_bulk", &bulk)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("elasticsearch bulk status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}
