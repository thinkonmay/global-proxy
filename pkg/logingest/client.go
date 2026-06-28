package logingest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const defaultBulkTimeout = 5 * time.Second

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9._\-+/=]{20,}`),
	regexp.MustCompile(`(?i)eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`),
	regexp.MustCompile(`(?i)vault\.password\s*[:=]\s*\S+`),
}

// Client bulk-indexes worker log documents into Elasticsearch.
type Client struct {
	esURL   string
	http    *http.Client
	maxBody int
}

func NewClient(esURL string, maxBody int) *Client {
	if maxBody <= 0 {
		maxBody = 1 << 20
	}
	return &Client{
		esURL:   strings.TrimRight(strings.TrimSpace(esURL), "/"),
		http:    &http.Client{Timeout: defaultBulkTimeout},
		maxBody: maxBody,
	}
}

func (c *Client) Enabled() bool {
	return c != nil && c.esURL != ""
}

// IndexDocument writes one log document to worker-logs-{yyyy.MM.dd}.
func (c *Client) IndexDocument(ctx context.Context, doc map[string]any) error {
	if !c.Enabled() {
		return fmt.Errorf("elasticsearch url not configured")
	}
	redactDocument(doc)
	ts := time.Now().UTC()
	if raw, ok := doc["@timestamp"].(string); ok && raw != "" {
		if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
			ts = t.UTC()
		} else if t, err := time.Parse(time.RFC3339, raw); err == nil {
			ts = t.UTC()
		}
	}
	index := fmt.Sprintf("worker-logs-%s", ts.Format("2006.01.02"))
	body, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	action := fmt.Sprintf(`{"index":{"_index":"%s"}}`, index)
	payload := action + "\n" + string(body) + "\n"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.esURL+"/_bulk", strings.NewReader(payload))
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

// IndexNDJSON parses NDJSON worker log push bodies and bulk-indexes them.
func (c *Client) IndexNDJSON(ctx context.Context, body []byte) error {
	if !c.Enabled() {
		return fmt.Errorf("elasticsearch url not configured")
	}
	lines := bytes.Split(body, []byte("\n"))
	var bulk bytes.Buffer
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var doc map[string]any
		if err := json.Unmarshal(line, &doc); err != nil {
			continue
		}
		redactDocument(doc)
		ts := time.Now().UTC()
		if raw, ok := doc["@timestamp"].(string); ok && raw != "" {
			if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
				ts = t.UTC()
			} else if t, err := time.Parse(time.RFC3339, raw); err == nil {
				ts = t.UTC()
			}
		}
		index := fmt.Sprintf("worker-logs-%s", ts.Format("2006.01.02"))
		action := fmt.Sprintf(`{"index":{"_index":"%s"}}`, index)
		docLine, err := json.Marshal(doc)
		if err != nil {
			continue
		}
		bulk.WriteString(action)
		bulk.WriteByte('\n')
		bulk.Write(docLine)
		bulk.WriteByte('\n')
		if bulk.Len() > c.maxBody {
			break
		}
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

func redactDocument(doc map[string]any) {
	if msg, ok := doc["message"].(string); ok {
		doc["message"] = redactSecrets(msg)
	}
}

func redactSecrets(s string) string {
	out := s
	for _, re := range secretPatterns {
		out = re.ReplaceAllString(out, "[REDACTED]")
	}
	return out
}
