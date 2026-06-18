// Package postgrest is a thin HTTP client for a PostgREST server. The gateway
// uses it instead of a direct Postgres connection (see doc/architecture.md §1):
// global data is reached over /rest/v1, never via pgx.
package postgrest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// defaultTimeout bounds every outbound call (TDD §2.1.1; checklist G2).
const defaultTimeout = 5 * time.Second

type Config struct {
	URL        string
	AnonKey    string
	ServiceKey string
}

type Client struct {
	baseURL    string
	anonKey    string
	serviceKey string
	http       *http.Client
	timeout    time.Duration
}

func New(cfg Config) *Client {
	return &Client{
		baseURL:    strings.TrimRight(cfg.URL, "/"),
		anonKey:    cfg.AnonKey,
		serviceKey: cfg.ServiceKey,
		http:       &http.Client{},
		timeout:    defaultTimeout,
	}
}

// writeKey is used for mutations; falls back to the anon key when no service
// key is configured.
func (c *Client) writeKey() string {
	if c.serviceKey != "" {
		return c.serviceKey
	}
	return c.anonKey
}

// Insert POSTs a row to the given table. When returnRep is true it asks
// PostgREST to echo the inserted row(s) back (used to recover generated ids).
func (c *Client) Insert(ctx context.Context, table string, body any, returnRep bool) ([]byte, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal body: %w", err)
	}

	req, err := c.newRequest(ctx, http.MethodPost, table, nil, bytes.NewReader(payload), c.writeKey())
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if returnRep {
		req.Header.Set("Prefer", "return=representation")
	}
	return c.do(req)
}

// Update PATCHes rows matching the query filter (e.g. id=eq.5) with body. When
// returnRep is true PostgREST echoes the updated row(s) back.
func (c *Client) Update(ctx context.Context, table string, q url.Values, body any, returnRep bool) ([]byte, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal body: %w", err)
	}

	req, err := c.newRequest(ctx, http.MethodPatch, table, q, bytes.NewReader(payload), c.writeKey())
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if returnRep {
		req.Header.Set("Prefer", "return=representation")
	}
	return c.do(req)
}

// Select GETs rows from the given table using PostgREST query params (e.g.
// id=eq.5). An empty result is a valid `[]` body, not an error.
func (c *Client) Select(ctx context.Context, table string, q url.Values) ([]byte, error) {
	req, err := c.newRequest(ctx, http.MethodGet, table, q, nil, c.anonKey)
	if err != nil {
		return nil, err
	}
	return c.do(req)
}

func (c *Client) newRequest(ctx context.Context, method, table string, q url.Values, body io.Reader, key string) (*http.Request, error) {
	u := c.baseURL + "/" + strings.TrimLeft(table, "/")
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("apikey", key)
	req.Header.Set("Authorization", "Bearer "+key)
	return req, nil
}

func (c *Client) do(req *http.Request) ([]byte, error) {
	ctx, cancel := context.WithTimeout(req.Context(), c.timeout)
	defer cancel()

	resp, err := c.http.Do(req.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("postgrest %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("postgrest %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, data)
	}
	return data, nil
}
