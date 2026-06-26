package grant

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/httpx"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/pkg/router"
	"github.com/thinkonmay/global-proxy/api/pkg/storj"
)

const grantTimeout = 2 * time.Second

type Handler struct {
	pr    *postgrest.Client
	storj *storj.Client
}

func New(cfg config.Config, pr *postgrest.Client, rt http.RoundTripper) *Handler {
	_ = rt
	var st *storj.Client
	if grant := strings.TrimSpace(cfg.Storj.AccessGrant); grant != "" {
		if c, err := storj.New(grant, 24*time.Hour); err == nil {
			st = c
		}
	}
	return &Handler{pr: pr, storj: st}
}

func (h *Handler) Register(mux *http.ServeMux) {
	v1 := router.V1(mux)
	v1.GET("/storage/grant", h.StorageGrant)
	v1.GET("/app-access/claim", h.AppAccessClaim)
}

func (h *Handler) StorageGrant(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	cluster := r.URL.Query().Get("cluster")
	if email == "" || cluster == "" {
		httpx.WriteError(w, http.StatusBadRequest, "email and cluster required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), grantTimeout)
	defer cancel()
	var cred map[string]any
	err := h.pr.RPC(ctx, "grant_bucket_access_v1", map[string]any{
		"email":  email,
		"domain": httpx.ClusterHost(cluster),
	}, &cred)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"global_unavailable":true}`))
		return
	}
	if h.storj != nil {
		if name, ok := cred["bucket_name"].(string); ok && name != "" {
			_ = h.storj.CreateBucket(name)
		}
	}
	httpx.WriteJSON(w, http.StatusOK, cred)
}

func (h *Handler) AppAccessClaim(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	cluster := r.URL.Query().Get("cluster")
	appID := r.URL.Query().Get("app_id")
	if email == "" || cluster == "" {
		httpx.WriteError(w, http.StatusBadRequest, "email and cluster required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), grantTimeout)
	defer cancel()
	args := map[string]any{
		"email":  email,
		"domain": httpx.ClusterHost(cluster),
	}
	if appID != "" {
		args["app_id"] = appID
	}
	var cred map[string]any
	err := h.pr.RPC(ctx, "grant_app_access_v1", args, &cred)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"global_unavailable":true}`))
		return
	}
	httpx.WriteJSON(w, http.StatusOK, cred)
}
