package clusterproxy

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/auth"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/httpx"
)

// ForwardOpts configures an authenticated cluster HTTP forward.
type ForwardOpts struct {
	UpstreamPath  string
	RequireUser   bool
	ClusterSecret string
	UserEmail     string
	Timeout       time.Duration
	Transport     http.RoundTripper
}

// Forward resolves cluster=, optionally validates GoTrue JWT, and proxies to the node PocketBase route.
func Forward(w http.ResponseWriter, r *http.Request, opts ForwardOpts) {
	cluster := strings.TrimSpace(r.URL.Query().Get("cluster"))
	if cluster == "" {
		httpx.WriteError(w, http.StatusBadRequest, "cluster query required")
		return
	}

	email := strings.TrimSpace(opts.UserEmail)
	if opts.RequireUser {
		authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
		if authHeader == "" {
			httpx.WriteError(w, http.StatusUnauthorized, "authorization required")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		var status int
		var msg string
		email, _, status, msg = auth.ValidateRequest(ctx, r, opts.Transport)
		if status != 0 {
			httpx.WriteError(w, status, msg)
			return
		}
	}

	base, code, msg := auth.ResolveClusterURL(r.Context(), cluster)
	if code != 0 {
		httpx.WriteError(w, code, msg)
		return
	}

	target, err := url.Parse(base + opts.UpstreamPath)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid cluster")
		return
	}
	q := target.Query()
	for k, vals := range r.URL.Query() {
		if k == "cluster" {
			continue
		}
		for _, v := range vals {
			q.Add(k, v)
		}
	}
	target.RawQuery = q.Encode()

	var ctx context.Context
	var cancel context.CancelFunc
	if opts.Timeout == 0 && strings.Contains(opts.UpstreamPath, "/sse") {
		ctx, cancel = context.WithCancel(r.Context())
	} else {
		timeout := opts.Timeout
		if timeout == 0 {
			timeout = DefaultTimeout * time.Second
		}
		ctx, cancel = httpx.ContextWithTimeout(r.Context(), timeout)
	}
	defer cancel()

	var body io.Reader
	if r.Body != nil && r.Method != http.MethodGet && r.Method != http.MethodHead {
		body = r.Body
	}
	req, err := http.NewRequestWithContext(ctx, r.Method, target.String(), body)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "build request failed")
		return
	}
	req.Header.Set(InternalHeader, "1")
	if secret := strings.TrimSpace(opts.ClusterSecret); secret != "" {
		req.Header.Set(SecretHeader, secret)
	}
	if email != "" {
		req.Header.Set(UserEmailHeader, email)
	}
	for _, k := range []string{"Content-Type", "Accept", "Range"} {
		if v := r.Header.Get(k); v != "" {
			req.Header.Set(k, v)
		}
	}

	rt := opts.Transport
	if rt == nil {
		rt = http.DefaultTransport
	}
	client := &http.Client{
		Transport: rt,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if opts.Timeout == 0 && strings.Contains(opts.UpstreamPath, "/sse") {
		client.Timeout = 0
	} else {
		client.Timeout = DefaultTimeout * time.Second
		if opts.Timeout > 0 {
			client.Timeout = opts.Timeout
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "cluster unreachable")
		return
	}
	defer func() { _ = resp.Body.Close() }()

	httpx.CopyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}
