package handler

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	gatewayInternalHeader = "X-Thinkmay-Gateway-Internal"
	nodeProxyTimeout      = 120 * time.Second
)

// NodeProxyHandler forwards snapshot operations to node PocketBase internal routes.
type NodeProxyHandler struct {
	httpClient *http.Client
}

func NewNodeProxyHandler(rt http.RoundTripper) *NodeProxyHandler {
	if rt == nil {
		rt = http.DefaultTransport
	}
	return &NodeProxyHandler{
		httpClient: &http.Client{
			Timeout:   nodeProxyTimeout,
			Transport: rt,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (h *NodeProxyHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/pb-proxy/snapshots", h.proxySnapshots)
	mux.HandleFunc("POST /v1/pb-proxy/snapshots/restore", h.proxySnapshotsRestore)

	mux.HandleFunc("GET /v1/volumes/snapshots", h.proxySnapshots)
	mux.HandleFunc("POST /v1/volumes/snapshots/restore", h.proxySnapshotsRestore)
}

func (h *NodeProxyHandler) proxySnapshots(w http.ResponseWriter, r *http.Request) {
	h.forward(w, r, "/internal/snapshots")
}

func (h *NodeProxyHandler) proxySnapshotsRestore(w http.ResponseWriter, r *http.Request) {
	h.forward(w, r, "/internal/snapshots/restore")
}

func (h *NodeProxyHandler) forward(w http.ResponseWriter, r *http.Request, pbPath string) {
	cluster := strings.TrimSpace(r.URL.Query().Get("cluster"))
	if cluster == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cluster query required"})
		return
	}
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if auth == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authorization required"})
		return
	}

	base := clusterBaseURL(cluster)
	target, err := url.Parse(base + pbPath)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid cluster"})
		return
	}
	target.RawQuery = r.URL.RawQuery

	ctx, cancel := contextWithTimeout(r.Context(), nodeProxyTimeout)
	defer cancel()

	var body io.Reader
	if r.Body != nil && r.Method != http.MethodGet && r.Method != http.MethodHead {
		body = r.Body
	}
	req, err := http.NewRequestWithContext(ctx, r.Method, target.String(), body)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "build request failed"})
		return
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set(gatewayInternalHeader, "1")
	for _, k := range []string{"Content-Type", "Accept", "Range"} {
		if v := r.Header.Get(k); v != "" {
			req.Header.Set(k, v)
		}
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "cluster unreachable"})
		return
	}
	defer func() { _ = resp.Body.Close() }()

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func clusterBaseURL(cluster string) string {
	cluster = strings.TrimSpace(cluster)
	if cluster == "" {
		return ""
	}
	if strings.HasPrefix(cluster, "http://") || strings.HasPrefix(cluster, "https://") {
		return strings.TrimRight(cluster, "/")
	}
	return "https://" + strings.TrimRight(cluster, "/")
}

func copyHeader(dst, src http.Header) {
	for k, vals := range src {
		if strings.EqualFold(k, "Transfer-Encoding") {
			continue
		}
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
}

func contextWithTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(ctx, d)
}
