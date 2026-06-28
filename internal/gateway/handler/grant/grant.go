package grant

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/auth"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/httpx"
	"github.com/thinkonmay/global-proxy/api/pkg/cluster"
	"github.com/thinkonmay/global-proxy/api/pkg/grants"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/pkg/router"
	"github.com/thinkonmay/global-proxy/api/pkg/storj"
)

const grantTimeout = 2 * time.Second

type Handler struct {
	pr        *postgrest.Client
	storj     *storj.Client
	transport http.RoundTripper
}

func New(pr *postgrest.Client, st *storj.Client, rt http.RoundTripper) *Handler {
	if rt == nil {
		rt = http.DefaultTransport
	}
	return &Handler{pr: pr, storj: st, transport: rt}
}

func (h *Handler) Register(mux *http.ServeMux) {
	v1 := router.V1(mux)
	v1.GET("/storage/grant", h.StorageGrant)
	v1.GET("/app-access/claim", h.AppAccessClaim)
	v1.GET("/app-access/claim/{appId}", h.AppAccessClaim)
}

func (h *Handler) resolveGrantDomain(ctx context.Context, r *http.Request, email string) (string, int, string) {
	volumeID := strings.TrimSpace(r.URL.Query().Get("volume_id"))
	domain, err := cluster.ResolveGrantDomain(ctx, h.pr, email, volumeID)
	if err != nil {
		return "", http.StatusBadRequest, err.Error()
	}
	return domain, 0, ""
}

func (h *Handler) StorageGrant(w http.ResponseWriter, r *http.Request) {
	email, ok, status, msg := auth.RequireUser(r.Context(), r, h.transport)
	if !ok {
		auth.WriteAuthErr(w, status, msg)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), grantTimeout)
	defer cancel()
	domain, code, msg := h.resolveGrantDomain(ctx, r, email)
	if code != 0 {
		httpx.WriteError(w, code, msg)
		return
	}
	cred, err := grants.GrantBucketAccess(ctx, h.pr, h.storj, email, domain)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"global_unavailable":true}`))
		return
	}
	httpx.WriteJSON(w, http.StatusOK, cred)
}

func (h *Handler) AppAccessClaim(w http.ResponseWriter, r *http.Request) {
	email, ok, status, msg := auth.RequireUser(r.Context(), r, h.transport)
	if !ok {
		auth.WriteAuthErr(w, status, msg)
		return
	}
	appID := strings.TrimSpace(r.PathValue("appId"))
	ctx, cancel := context.WithTimeout(r.Context(), grantTimeout)
	defer cancel()
	domain, code, msg := h.resolveGrantDomain(ctx, r, email)
	if code != 0 {
		httpx.WriteError(w, code, msg)
		return
	}
	claim, err := grants.GrantAndClaimApp(ctx, h.pr, email, domain, appID)
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
