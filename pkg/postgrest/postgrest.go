// Package postgrest is a thin HTTP client for PostgREST: data is reached over
// HTTP, never a direct Postgres connection (P2/P3). Methods decode the response
// into a caller-supplied dest.
package postgrest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// defaultTimeout bounds every outbound call (TDD §2.1.1; checklist G2).
const defaultTimeout = 5 * time.Second

// Error is returned for a non-2xx PostgREST response.
type Error struct {
	Status int
	Method string
	Path   string
	Body   []byte
}

func (e *Error) Error() string {
	return fmt.Sprintf("postgrest %s %s: status %d: %s", e.Method, e.Path, e.Status, e.Body)
}

// IsConflict reports whether err is a 409 from PostgREST (e.g. a unique/PK
// violation — used for idempotent "claim" inserts).
func IsConflict(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == http.StatusConflict
}

type Config struct {
	URL        string
	AnonKey    string
	ServiceKey string
	// Transport, if set, backs the HTTP client — pass a *guard.Transport for
	// circuit breaking + bulkhead. Nil = http.DefaultTransport.
	Transport http.RoundTripper
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
		http:       &http.Client{Transport: cfg.Transport},
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

// Insert POSTs body to table. Non-nil dest decodes the inserted row(s) back
// (e.g. to recover generated ids).
func (c *Client) Insert(ctx context.Context, table string, body, dest any) error {
	req, err := c.bodyRequest(ctx, http.MethodPost, table, nil, body, dest != nil)
	if err != nil {
		return err
	}
	return c.do(req, dest)
}

// Update PATCHes rows matching q with body. Non-nil dest decodes the updated row(s).
func (c *Client) Update(ctx context.Context, table string, q url.Values, body, dest any) error {
	req, err := c.bodyRequest(ctx, http.MethodPatch, table, q, body, dest != nil)
	if err != nil {
		return err
	}
	return c.do(req, dest)
}

// RPC calls a Postgres function via POST /rpc/<fn> — one transaction, the way to
// do atomic multi-statement work (PostgREST has no raw SQL). args is the JSON
// arg object (nil for none); non-nil dest decodes the result.
func (c *Client) RPC(ctx context.Context, fn string, args, dest any) error {
	req, err := c.bodyRequest(ctx, http.MethodPost, "rpc/"+strings.TrimLeft(fn, "/"), nil, args, false)
	if err != nil {
		return err
	}
	return c.do(req, dest)
}

// Select GETs rows matching q into dest. An empty result is a valid `[]`, not an error.
func (c *Client) Select(ctx context.Context, table string, q url.Values, dest any) error {
	req, err := c.newRequest(ctx, http.MethodGet, table, q, nil, c.anonKey)
	if err != nil {
		return err
	}
	return c.do(req, dest)
}

// SelectService GETs with the service_role key (gateway-trusted reads after auth).
func (c *Client) SelectService(ctx context.Context, table string, q url.Values, dest any) error {
	req, err := c.newRequest(ctx, http.MethodGet, table, q, nil, c.writeKey())
	if err != nil {
		return err
	}
	return c.do(req, dest)
}

// Delete removes rows matching q.
func (c *Client) Delete(ctx context.Context, table string, q url.Values) error {
	req, err := c.newRequest(ctx, http.MethodDelete, table, q, nil, c.writeKey())
	if err != nil {
		return err
	}
	return c.do(req, nil)
}

// bodyRequest builds a JSON-body request (POST/PATCH); returnRep asks PostgREST
// to echo the affected rows. args==nil sends no body (no-arg RPC).
func (c *Client) bodyRequest(ctx context.Context, method, table string, q url.Values, body any, returnRep bool) (*http.Request, error) {
	var r io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal body: %w", err)
		}
		r = bytes.NewReader(payload)
	}
	req, err := c.newRequest(ctx, method, table, q, r, c.writeKey())
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if returnRep {
		req.Header.Set("Prefer", "return=representation")
	}
	return req, nil
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

// do sends req and, on 2xx, decodes the body into dest when non-nil.
func (c *Client) do(req *http.Request, dest any) error {
	ctx, cancel := context.WithTimeout(req.Context(), c.timeout)
	defer cancel()

	resp, err := c.http.Do(req.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("postgrest %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &Error{Status: resp.StatusCode, Method: req.Method, Path: req.URL.Path, Body: data}
	}
	// A void-returning RPC replies 2xx with an empty body; there is nothing to
	// decode, so leave dest at its zero value instead of failing on empty input.
	if dest != nil && len(data) > 0 {
		if err := json.Unmarshal(data, dest); err != nil {
			return fmt.Errorf("decode %s: %w", req.URL.Path, err)
		}
	}
	return nil
}
