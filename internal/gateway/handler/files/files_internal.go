package files

import (
	"context"
	"net/http"
	"strings"

	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/httpx"
)

// SyncBucketSize updates global bucket size after a node session ends.
func (h *Handler) SyncBucketSize(w http.ResponseWriter, r *http.Request) {
	if h.storj == nil || h.pr == nil {
		httpx.WriteError(w, http.StatusServiceUnavailable, "storj unavailable")
		return
	}
	email := r.URL.Query().Get("email")
	cluster := httpx.ClusterHost(r.URL.Query().Get("cluster"))
	bucket := strings.TrimSpace(r.URL.Query().Get("bucket_name"))
	if email == "" || cluster == "" || bucket == "" {
		httpx.WriteError(w, http.StatusBadRequest, "email, cluster, bucket_name required")
		return
	}
	size, err := h.storj.BucketSize(bucket)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "stat bucket failed")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), grantTimeout)
	defer cancel()
	if err := h.pr.RPC(ctx, "sync_user_bucket_size_v1", map[string]any{
		"email":          email,
		"domain":         cluster,
		"new_size_bytes": size,
	}, nil); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "sync failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// IncrementAppAccessUsage bumps global app_access usage after a node session ends.
func (h *Handler) IncrementAppAccessUsage(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	cluster := httpx.ClusterHost(r.URL.Query().Get("cluster"))
	if email == "" || cluster == "" {
		httpx.WriteError(w, http.StatusBadRequest, "email and cluster required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), grantTimeout)
	defer cancel()
	if err := h.pr.RPC(ctx, "increment_user_app_access_usage_v1", map[string]any{
		"email":  email,
		"domain": cluster,
	}, nil); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "increment failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// IncrementLLMUsage bumps global LLM addon usage (node calls via gateway, not Postgres HTTP).
func (h *Handler) IncrementLLMUsage(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	cluster := httpx.ClusterHost(r.URL.Query().Get("cluster"))
	if email == "" || cluster == "" {
		httpx.WriteError(w, http.StatusBadRequest, "email and cluster required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), grantTimeout)
	defer cancel()
	if err := h.pr.RPC(ctx, "increment_user_llm_usage_v1", map[string]any{
		"email":  email,
		"domain": cluster,
	}, nil); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "increment failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// LookupUserAppAccess returns app_id for node /new hydration.
func (h *Handler) LookupAppAccess(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	cluster := httpx.ClusterHost(r.URL.Query().Get("cluster"))
	if email == "" || cluster == "" {
		httpx.WriteError(w, http.StatusBadRequest, "email and cluster required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), grantTimeout)
	defer cancel()
	var lookup map[string]any
	if err := h.pr.RPC(ctx, "lookup_user_app_access_v1", map[string]any{
		"email":  email,
		"domain": cluster,
	}, &lookup); err != nil || lookup == nil {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, lookup)
}
