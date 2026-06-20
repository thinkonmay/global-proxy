package handler

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/pkg/storj"
)

const grantTimeout = 2 * time.Second

type GrantHandler struct {
	pr    *postgrest.Client
	storj *storj.Client
}

func NewGrantHandler(cfg config.Config, pr *postgrest.Client, rt http.RoundTripper) *GrantHandler {
	_ = rt
	var st *storj.Client
	if grant := strings.TrimSpace(cfg.Storj.AccessGrant); grant != "" {
		if c, err := storj.New(grant, 24*time.Hour); err == nil {
			st = c
		}
	}
	return &GrantHandler{pr: pr, storj: st}
}

func (h *GrantHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/storage/grant", h.StorageGrant)
	mux.HandleFunc("GET /v1/app-access/claim", h.AppAccessClaim)
}

func (h *GrantHandler) StorageGrant(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	cluster := r.URL.Query().Get("cluster")
	if email == "" || cluster == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email and cluster required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), grantTimeout)
	defer cancel()
	var cred map[string]any
	err := h.pr.RPC(ctx, "grant_bucket_access_v1", map[string]any{
		"email":  email,
		"domain": clusterHost(cluster),
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
	writeJSON(w, http.StatusOK, cred)
}

func (h *GrantHandler) AppAccessClaim(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	cluster := r.URL.Query().Get("cluster")
	appID := r.URL.Query().Get("app_id")
	if email == "" || cluster == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email and cluster required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), grantTimeout)
	defer cancel()
	args := map[string]any{
		"email":  email,
		"domain": clusterHost(cluster),
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
	writeJSON(w, http.StatusOK, cred)
}
