package nodeproxy

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/auth"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/httpx"
)

const (
	gatewayInternalHeader = "X-Thinkmay-Gateway-Internal"
	nodeProxyTimeout      = 120 * time.Second
)

// Handler forwards snapshot operations to node PocketBase internal routes.
type Handler struct {
	httpClient *http.Client
}

func New(rt http.RoundTripper) *Handler {
	if rt == nil {
		rt = http.DefaultTransport
	}
	return &Handler{
		httpClient: &http.Client{
			Timeout:   nodeProxyTimeout,
			Transport: rt,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/pb-proxy/snapshots", h.proxySnapshots)
	mux.HandleFunc("POST /v1/pb-proxy/snapshots/restore", h.proxySnapshotsRestore)

	mux.HandleFunc("GET /v1/volumes/snapshots", h.proxySnapshots)
	mux.HandleFunc("POST /v1/volumes/snapshots/restore", h.proxySnapshotsRestore)
}

func (h *Handler) proxySnapshots(w http.ResponseWriter, r *http.Request) {
	h.forward(w, r, "/internal/snapshots")
}

func (h *Handler) proxySnapshotsRestore(w http.ResponseWriter, r *http.Request) {
	h.forward(w, r, "/internal/snapshots/restore")
}

func (h *Handler) forward(w http.ResponseWriter, r *http.Request, pbPath string) {
	cluster := strings.TrimSpace(r.URL.Query().Get("cluster"))
	if cluster == "" {
		httpx.WriteError(w, http.StatusBadRequest, "cluster query required")
		return
	}
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if authHeader == "" {
		httpx.WriteError(w, http.StatusUnauthorized, "authorization required")
		return
	}

	base, code, msg := auth.ResolveClusterURL(r.Context(), cluster)
	if code != 0 {
		httpx.WriteError(w, code, msg)
		return
	}
	target, err := url.Parse(base + pbPath)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid cluster")
		return
	}
	target.RawQuery = r.URL.RawQuery

	ctx, cancel := httpx.ContextWithTimeout(r.Context(), nodeProxyTimeout)
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
	req.Header.Set("Authorization", authHeader)
	req.Header.Set(gatewayInternalHeader, "1")
	for _, k := range []string{"Content-Type", "Accept", "Range"} {
		if v := r.Header.Get(k); v != "" {
			req.Header.Set(k, v)
		}
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "cluster unreachable")
		return
	}
	defer func() { _ = resp.Body.Close() }()

	httpx.CopyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}
