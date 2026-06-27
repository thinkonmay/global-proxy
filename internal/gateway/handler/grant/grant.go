package grant

import (
	"context"
	"net/http"
	"time"

	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/httpx"
	"github.com/thinkonmay/global-proxy/api/pkg/grants"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/pkg/router"
	"github.com/thinkonmay/global-proxy/api/pkg/storj"
)

const grantTimeout = 2 * time.Second

type Handler struct {
	pr    *postgrest.Client
	storj *storj.Client
}

func New(pr *postgrest.Client, st *storj.Client) *Handler {
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
	cred, err := grants.GrantBucketAccess(ctx, h.pr, h.storj, email, httpx.ClusterHost(cluster))
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"global_unavailable":true}`))
		return
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
	claim, err := grants.GrantAndClaimApp(ctx, h.pr, email, httpx.ClusterHost(cluster), appID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"global_unavailable":true}`))
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"app_id":   claim.AppID,
		"id":       claim.KeepaliveID,
		"username": claim.Username,
		"password": claim.Password,
		"depotKey": claim.DepotKey,
	})
}
