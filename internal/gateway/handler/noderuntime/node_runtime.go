package noderuntime

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/httpx"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

const nodeRuntimeTimeout = 30 * time.Second

// Handler serves node→global calls that previously hit PostgREST /rest/v1/rpc/*.
type Handler struct {
	pr         *postgrest.Client
	serviceKey string
}

func New(pr *postgrest.Client, serviceKey string) *Handler {
	return &Handler{pr: pr, serviceKey: strings.TrimSpace(serviceKey)}
}

func (h *Handler) Register(mux *http.ServeMux) {
	routes := []struct {
		method string
		path   string
		fn     http.HandlerFunc
	}{
		{http.MethodPost, "/v1/app-access/steam/claim", h.SteamClaim},
		{http.MethodPost, "/v1/app-access/steam/unclaim", h.SteamUnclaim},
		{http.MethodPost, "/v1/node/keepalive", h.Keepalive},
		{http.MethodPost, "/v1/node/volumes/sync", h.SyncVolume},
	}
	for _, route := range routes {
		mux.HandleFunc(route.method+" "+route.path, route.fn)
		mux.HandleFunc(route.method+" "+route.path+"/", route.fn)
	}
}

func (h *Handler) requireServiceKey(r *http.Request) bool {
	if h.serviceKey == "" {
		return true
	}
	if key := strings.TrimSpace(r.Header.Get("apikey")); key == h.serviceKey {
		return true
	}
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		return strings.TrimSpace(auth[7:]) == h.serviceKey
	}
	return false
}

func (h *Handler) writeServiceKeyErr(w http.ResponseWriter) {
	httpx.WriteError(w, http.StatusUnauthorized, "invalid service credentials")
}

func (h *Handler) SteamClaim(w http.ResponseWriter, r *http.Request) {
	if !h.requireServiceKey(r) {
		h.writeServiceKeyErr(w)
		return
	}
	var body struct {
		AppID string `json:"app_id"`
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.AppID == "" || body.Email == "" {
		httpx.WriteError(w, http.StatusBadRequest, "app_id and email required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), nodeRuntimeTimeout)
	defer cancel()

	var rows json.RawMessage
	if err := h.pr.RPC(ctx, "claim_v1", map[string]any{
		"app_id": body.AppID,
		"email":  body.Email,
	}, &rows); err != nil {
		httpx.WriteUpstreamErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, rows)
}

func (h *Handler) SteamUnclaim(w http.ResponseWriter, r *http.Request) {
	if !h.requireServiceKey(r) {
		h.writeServiceKeyErr(w)
		return
	}
	var body struct {
		KeepaliveID int32 `json:"keepaliveid"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.KeepaliveID <= 0 {
		httpx.WriteError(w, http.StatusBadRequest, "keepaliveid required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), nodeRuntimeTimeout)
	defer cancel()

	var out json.RawMessage
	if err := h.pr.RPC(ctx, "unclaim_v1", map[string]any{
		"keepaliveid": body.KeepaliveID,
	}, &out); err != nil {
		httpx.WriteUpstreamErr(w, err)
		return
	}
	httpx.WriteData(w, out)
}

func (h *Handler) Keepalive(w http.ResponseWriter, r *http.Request) {
	if !h.requireServiceKey(r) {
		h.writeServiceKeyErr(w)
		return
	}
	var body struct {
		ID int32 `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID <= 0 {
		httpx.WriteError(w, http.StatusBadRequest, "id required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), nodeRuntimeTimeout)
	defer cancel()

	var out json.RawMessage
	if err := h.pr.RPC(ctx, "keepalive_v1", map[string]any{"id": body.ID}, &out); err != nil {
		httpx.WriteUpstreamErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (h *Handler) SyncVolume(w http.ResponseWriter, r *http.Request) {
	if !h.requireServiceKey(r) {
		h.writeServiceKeyErr(w)
		return
	}
	var body struct {
		Email         string `json:"email"`
		VolumeID      string `json:"volume_id"`
		ClusterDomain string `json:"cluster_domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.Email == "" || body.VolumeID == "" || body.ClusterDomain == "" {
		httpx.WriteError(w, http.StatusBadRequest, "email, volume_id, and cluster_domain required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), nodeRuntimeTimeout)
	defer cancel()

	var out json.RawMessage
	if err := h.pr.RPC(ctx, "sync_volume_data_v1", map[string]any{
		"email":          body.Email,
		"volume_id":      body.VolumeID,
		"cluster_domain": body.ClusterDomain,
	}, &out); err != nil {
		httpx.WriteUpstreamErr(w, err)
		return
	}
	httpx.WriteData(w, out)
}
