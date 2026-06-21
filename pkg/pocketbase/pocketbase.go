// Package pocketbase is a thin HTTP client for cluster PocketBase admin APIs.
// It logs in once via _superusers auth-with-password and reuses the bearer token
// on subsequent calls. Tokens are proactively renewed every hour and again on
// 401/403 (PocketBase often returns 403 for invalid superuser tokens).
//
// API shapes follow https://pocketbase.io/docs/api-records/ (auth-with-password,
// auth-refresh, collection records).
package pocketbase

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
	"sync"
	"time"
)

const (
	defaultTimeout       = 5 * time.Second
	tokenRefreshInterval = time.Hour
	superusers           = "_superusers"
	usersCollection  = "users"
	authWithPassword = "/api/collections/" + superusers + "/auth-with-password"
	authRefreshPath  = "/api/collections/" + superusers + "/auth-refresh"
)

// Error is returned for a non-2xx PocketBase response.
type Error struct {
	Status int
	Method string
	Path   string
	Body   []byte
}

func (e *Error) Error() string {
	return fmt.Sprintf("pocketbase %s %s: status %d: %s", e.Method, e.Path, e.Status, e.Body)
}

// IsNotFound reports whether err is a 404 from PocketBase.
func IsNotFound(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == http.StatusNotFound
}

// AuthResponse is the PocketBase auth-with-password / auth-refresh payload.
type AuthResponse struct {
	Token  string          `json:"token"`
	Record json.RawMessage `json:"record"`
}

// Config holds cluster PocketBase connection settings.
type Config struct {
	URL       string
	Username  string
	Password  string
	Transport http.RoundTripper
	Timeout   time.Duration
}

// RequestOption customizes an outbound PocketBase call.
type RequestOption func(*requestConfig)

type requestConfig struct {
	headers http.Header
}

// WithHeaders attaches extra request headers (e.g. Idempotency-Key).
func WithHeaders(h http.Header) RequestOption {
	return func(rc *requestConfig) {
		if len(h) > 0 {
			rc.headers = h.Clone()
		}
	}
}

// Client calls cluster PocketBase with a cached superuser token.
type Client struct {
	baseURL  string
	username string
	password string
	http     *http.Client
	timeout  time.Duration

	mu            sync.Mutex
	authToken     string
	tokenIssuedAt time.Time
}

// New builds a client for cfg.URL. Use WithBaseURL for other cluster domains.
func New(cfg Config) *Client {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &Client{
		baseURL:  strings.TrimRight(cfg.URL, "/"),
		username: strings.TrimSpace(cfg.Username),
		password: cfg.Password,
		http:     &http.Client{Transport: cfg.Transport},
		timeout:  timeout,
	}
}

// Configured reports whether URL and superuser credentials are set.
func (c *Client) Configured() bool {
	return c.baseURL != "" && c.username != "" && c.password != ""
}

// WithBaseURL returns a client for another cluster domain, sharing credentials
// and transport but maintaining a separate token cache.
func (c *Client) WithBaseURL(rawURL string) *Client {
	next := strings.TrimRight(rawURL, "/")
	if next == "" || next == c.baseURL {
		return c
	}
	return &Client{
		baseURL:  next,
		username: c.username,
		password: c.password,
		http:     c.http,
		timeout:  c.timeout,
	}
}

// Get issues an authenticated GET to path (e.g. /api/collections/users/records).
func (c *Client) Get(ctx context.Context, path string, q url.Values, dest any, opts ...RequestOption) error {
	return c.Do(ctx, http.MethodGet, path, q, nil, dest, opts...)
}

// Post issues an authenticated POST with a JSON body.
func (c *Client) Post(ctx context.Context, path string, body, dest any, opts ...RequestOption) error {
	return c.Do(ctx, http.MethodPost, path, nil, body, dest, opts...)
}

// Patch issues an authenticated PATCH with a JSON body.
func (c *Client) Patch(ctx context.Context, path string, body, dest any, opts ...RequestOption) error {
	return c.Do(ctx, http.MethodPatch, path, nil, body, dest, opts...)
}

// Delete issues an authenticated DELETE.
func (c *Client) Delete(ctx context.Context, path string, q url.Values, opts ...RequestOption) error {
	return c.Do(ctx, http.MethodDelete, path, q, nil, nil, opts...)
}

// ListRecords GETs /api/collections/{collection}/records with optional filter query.
func (c *Client) ListRecords(ctx context.Context, collection string, q url.Values, dest any, opts ...RequestOption) error {
	path := "/api/collections/" + strings.Trim(collection, "/") + "/records"
	return c.Get(ctx, path, q, dest, opts...)
}

// GetRecord GETs a single record by id.
func (c *Client) GetRecord(ctx context.Context, collection, id string, dest any, opts ...RequestOption) error {
	path := fmt.Sprintf("/api/collections/%s/records/%s", strings.Trim(collection, "/"), id)
	return c.Get(ctx, path, nil, dest, opts...)
}

// CreateRecord POSTs to /api/collections/{collection}/records.
func (c *Client) CreateRecord(ctx context.Context, collection string, body, dest any, opts ...RequestOption) error {
	path := "/api/collections/" + strings.Trim(collection, "/") + "/records"
	return c.Post(ctx, path, body, dest, opts...)
}

// UpdateRecord PATCHes /api/collections/{collection}/records/{id}.
func (c *Client) UpdateRecord(ctx context.Context, collection, id string, body, dest any, opts ...RequestOption) error {
	path := fmt.Sprintf("/api/collections/%s/records/%s", strings.Trim(collection, "/"), id)
	return c.Patch(ctx, path, body, dest, opts...)
}

// DeleteRecord DELETEs /api/collections/{collection}/records/{id}.
func (c *Client) DeleteRecord(ctx context.Context, collection, id string, opts ...RequestOption) error {
	path := fmt.Sprintf("/api/collections/%s/records/%s", strings.Trim(collection, "/"), id)
	return c.Delete(ctx, path, nil, opts...)
}

// Do sends an authenticated request to path (leading slash optional).
func (c *Client) Do(ctx context.Context, method, path string, q url.Values, body, dest any, opts ...RequestOption) error {
	if !c.Configured() {
		return errors.New("pocketbase: url, username, and password required")
	}
	var rc requestConfig
	for _, opt := range opts {
		opt(&rc)
	}
	req, err := c.newRequest(ctx, method, path, q, body)
	if err != nil {
		return err
	}
	applyHeaders(req, rc.headers)
	return c.doWithAuth(ctx, req, dest, true)
}

// RefreshAuth POSTs /api/collections/{collection}/auth-refresh with the caller token.
func RefreshAuth(ctx context.Context, clientIssuer, collection, authorization string, rt http.RoundTripper) (*AuthResponse, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(clientIssuer), "/")
	path := "/api/collections/" + strings.Trim(collection, "/") + "/auth-refresh"
	u := baseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", bearerToken(authorization))

	client := &http.Client{Transport: rt}
	if client.Transport == nil {
		client.Transport = http.DefaultTransport
	}
	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("pocketbase auth-refresh: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read auth-refresh body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &Error{Status: resp.StatusCode, Method: http.MethodPost, Path: path, Body: data}
	}
	var out AuthResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("decode auth-refresh: %w", err)
	}
	return &out, nil
}

// UserEmailFromRefresh validates a users-collection token via auth-refresh
// and returns the record email.
func UserEmailFromRefresh(ctx context.Context, clientIssuer, authorization string, rt http.RoundTripper) (string, error) {
	resp, err := RefreshAuth(ctx, clientIssuer, usersCollection, authorization, rt)
	if err != nil {
		return "", err
	}
	var record struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(resp.Record, &record); err != nil {
		return "", fmt.Errorf("decode auth record: %w", err)
	}
	if record.Email == "" {
		return "", errors.New("empty pocketbase user email")
	}
	return record.Email, nil
}

func (c *Client) newRequest(ctx context.Context, method, path string, q url.Values, body any) (*http.Request, error) {
	path = "/" + strings.TrimLeft(path, "/")
	u := c.baseURL + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var r io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal body: %w", err)
		}
		r = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, r)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

func (c *Client) doWithAuth(ctx context.Context, req *http.Request, dest any, allowRetry bool) error {
	tok, err := c.ensureToken(ctx)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", bearerToken(tok))

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	resp, err := c.http.Do(req.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("pocketbase %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	if (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) && allowRetry {
		if err := c.recoverAuth(ctx); err != nil {
			return err
		}
		retry, err := cloneRequest(ctx, req)
		if err != nil {
			return err
		}
		return c.doWithAuth(ctx, retry, dest, false)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &Error{Status: resp.StatusCode, Method: req.Method, Path: req.URL.Path, Body: data}
	}
	if dest != nil {
		if err := json.Unmarshal(data, dest); err != nil {
			return fmt.Errorf("decode %s: %w", req.URL.Path, err)
		}
	}
	return nil
}

func (c *Client) ensureToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.authToken == "" {
		if err := c.loginLocked(ctx); err != nil {
			return "", err
		}
		return c.authToken, nil
	}
	if !c.tokenIssuedAt.IsZero() && time.Since(c.tokenIssuedAt) >= tokenRefreshInterval {
		if err := c.renewLocked(ctx); err != nil {
			return "", err
		}
	}
	return c.authToken, nil
}

func (c *Client) recoverAuth(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.renewLocked(ctx)
}

// renewLocked refreshes the cached token or falls back to password login.
// Caller must hold c.mu.
func (c *Client) renewLocked(ctx context.Context) error {
	if c.authToken != "" {
		if err := c.refreshLocked(ctx); err == nil {
			return nil
		}
	}
	c.authToken = ""
	c.tokenIssuedAt = time.Time{}
	return c.loginLocked(ctx)
}

func (c *Client) loginLocked(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+authWithPassword, bytes.NewReader(mustJSON(map[string]string{
		"identity": c.username,
		"password": c.password,
	})))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	resp, err := c.http.Do(req.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("pocketbase auth-with-password: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read auth body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return &Error{Status: resp.StatusCode, Method: http.MethodPost, Path: authWithPassword, Body: data}
	}
	var out AuthResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return fmt.Errorf("decode auth response: %w", err)
	}
	if out.Token == "" {
		return errors.New("pocketbase auth-with-password: empty token")
	}
	c.authToken = out.Token
	c.tokenIssuedAt = time.Now()
	return nil
}

func (c *Client) refreshLocked(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+authRefreshPath, http.NoBody)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", c.authToken)

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	resp, err := c.http.Do(req.WithContext(ctx))
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return &Error{Status: resp.StatusCode, Method: http.MethodPost, Path: authRefreshPath, Body: data}
	}
	var out AuthResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	if out.Token == "" {
		return errors.New("pocketbase auth-refresh: empty token")
	}
	c.authToken = out.Token
	c.tokenIssuedAt = time.Now()
	return nil
}

func cloneRequest(ctx context.Context, req *http.Request) (*http.Request, error) {
	var body io.Reader
	if req.Body != nil {
		data, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(data)
	}
	clone, err := http.NewRequestWithContext(ctx, req.Method, req.URL.String(), body)
	if err != nil {
		return nil, err
	}
	clone.Header = req.Header.Clone()
	clone.Header.Del("Authorization")
	return clone, nil
}

func applyHeaders(req *http.Request, h http.Header) {
	for k, vals := range h {
		for _, v := range vals {
			req.Header.Add(k, v)
		}
	}
}

func bearerToken(token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(token), "bearer ") {
		return token
	}
	return "Bearer " + token
}

func rawAuthToken(authorization string) string {
	token := strings.TrimSpace(authorization)
	if strings.HasPrefix(strings.ToLower(token), "bearer ") {
		return strings.TrimSpace(token[7:])
	}
	return token
}

func normalizeAuthHeader(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return v
	}
	if strings.HasPrefix(strings.ToLower(v), "bearer ") {
		return v
	}
	return v
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
