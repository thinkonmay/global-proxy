package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

const grantTimeout = 2 * time.Second

type GrantHandler struct {
	pr *postgrest.Client
}

func NewGrantHandler(cfg config.Config, pr *postgrest.Client, rt http.RoundTripper) *GrantHandler {
	_ = cfg
	_ = rt
	return &GrantHandler{pr: pr}
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
		"domain": cluster,
	}, &cred)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"global_unavailable":true}`))
		return
	}
	writeJSON(w, http.StatusOK, cred)
}

func (h *GrantHandler) AppAccessClaim(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	cluster := r.URL.Query().Get("cluster")
	if email == "" || cluster == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email and cluster required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), grantTimeout)
	defer cancel()
	var cred map[string]any
	err := h.pr.RPC(ctx, "grant_app_access_v1", map[string]any{
		"email":  email,
		"domain": cluster,
	}, &cred)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"global_unavailable":true}`))
		return
	}
	writeJSON(w, http.StatusOK, cred)
}
