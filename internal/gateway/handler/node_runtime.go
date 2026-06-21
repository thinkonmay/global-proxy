package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

const nodeRuntimeTimeout = 30 * time.Second

// NodeRuntimeHandler serves node→global calls that previously hit PostgREST /rest/v1/rpc/*.
type NodeRuntimeHandler struct {
	pr         *postgrest.Client
	serviceKey string
}

func NewNodeRuntimeHandler(pr *postgrest.Client, serviceKey string) *NodeRuntimeHandler {
	return &NodeRuntimeHandler{pr: pr, serviceKey: strings.TrimSpace(serviceKey)}
}

func (h *NodeRuntimeHandler) Register(mux *http.ServeMux) {
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

func (h *NodeRuntimeHandler) requireServiceKey(r *http.Request) bool {
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

func (h *NodeRuntimeHandler) writeServiceKeyErr(w http.ResponseWriter) {
	writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid service credentials"})
}

func (h *NodeRuntimeHandler) SteamClaim(w http.ResponseWriter, r *http.Request) {
	if !h.requireServiceKey(r) {
		h.writeServiceKeyErr(w)
		return
	}
	var body struct {
		AppID string `json:"app_id"`
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.AppID == "" || body.Email == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "app_id and email required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), nodeRuntimeTimeout)
	defer cancel()

	var rows json.RawMessage
	if err := h.pr.RPC(ctx, "claim_v1", map[string]any{
		"app_id": body.AppID,
		"email":  body.Email,
	}, &rows); err != nil {
		writeNodeRuntimeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

func (h *NodeRuntimeHandler) SteamUnclaim(w http.ResponseWriter, r *http.Request) {
	if !h.requireServiceKey(r) {
		h.writeServiceKeyErr(w)
		return
	}
	var body struct {
		KeepaliveID int32 `json:"keepaliveid"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.KeepaliveID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "keepaliveid required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), nodeRuntimeTimeout)
	defer cancel()

	var out json.RawMessage
	if err := h.pr.RPC(ctx, "unclaim_v1", map[string]any{
		"keepaliveid": body.KeepaliveID,
	}, &out); err != nil {
		writeNodeRuntimeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}

func (h *NodeRuntimeHandler) Keepalive(w http.ResponseWriter, r *http.Request) {
	if !h.requireServiceKey(r) {
		h.writeServiceKeyErr(w)
		return
	}
	var body struct {
		ID int32 `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), nodeRuntimeTimeout)
	defer cancel()

	var out json.RawMessage
	if err := h.pr.RPC(ctx, "keepalive_v1", map[string]any{"id": body.ID}, &out); err != nil {
		writeNodeRuntimeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *NodeRuntimeHandler) SyncVolume(w http.ResponseWriter, r *http.Request) {
	if !h.requireServiceKey(r) {
		h.writeServiceKeyErr(w)
		return
	}
	var body struct {
		Email          string `json:"email"`
		VolumeID       string `json:"volume_id"`
		ClusterDomain  string `json:"cluster_domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if body.Email == "" || body.VolumeID == "" || body.ClusterDomain == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email, volume_id, and cluster_domain required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), nodeRuntimeTimeout)
	defer cancel()

	var out json.RawMessage
	if err := h.pr.RPC(ctx, "sync_volume_data_v1", map[string]any{
		"email":           body.Email,
		"volume_id":       body.VolumeID,
		"cluster_domain":  body.ClusterDomain,
	}, &out); err != nil {
		writeNodeRuntimeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}

func writeNodeRuntimeErr(w http.ResponseWriter, err error) {
	var pe *postgrest.Error
	if errors.As(err, &pe) {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": strings.TrimSpace(string(pe.Body))})
		return
	}
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
}
