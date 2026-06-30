package catalog

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/httpx"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

func parseStorePathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	storeID := strings.TrimSpace(r.PathValue("storeID"))
	id, err := strconv.ParseInt(storeID, 10, 64)
	if storeID == "" || err != nil || id <= 0 {
		httpx.WriteError(w, http.StatusBadRequest, "store id required")
		return 0, false
	}
	return id, true
}

// EnsureStore creates a stub catalog.stores row for ops tooling (the-red).
func (h *Handler) EnsureStore(w http.ResponseWriter, r *http.Request) {
	id, ok := parseStorePathID(w, r)
	if !ok {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), catalogQueryTimeout)
	defer cancel()

	if err := h.pr.Insert(ctx, "stores", map[string]any{"id": id, "type": "STEAM"}, nil); err != nil {
		if !postgrest.IsConflict(err) {
			httpx.WritePostgrestErr(w, err)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// PutStoreDepotKeys upserts Steam depot decryption keys for a store.
func (h *Handler) PutStoreDepotKeys(w http.ResponseWriter, r *http.Request) {
	id, ok := parseStorePathID(w, r)
	if !ok {
		return
	}

	var body struct {
		Depotkey map[string]string `json:"depotkey"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(body.Depotkey) == 0 {
		httpx.WriteError(w, http.StatusBadRequest, "depotkey required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), catalogQueryTimeout)
	defer cancel()

	if err := h.pr.RPC(ctx, "upsert_store_depot_keys_v1", map[string]any{
		"store_id": id,
		"depotkey": body.Depotkey,
	}, nil); err != nil {
		httpx.WritePostgrestErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// PatchStoreDownloads replaces the catalog.stores download jsonb field.
func (h *Handler) PatchStoreDownloads(w http.ResponseWriter, r *http.Request) {
	storeID := strings.TrimSpace(r.PathValue("storeID"))
	if storeID == "" {
		httpx.WriteError(w, http.StatusBadRequest, "store id required")
		return
	}

	var body struct {
		Download []map[string]any `json:"download"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.Download == nil {
		httpx.WriteError(w, http.StatusBadRequest, "download required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), catalogQueryTimeout)
	defer cancel()

	q := url.Values{}
	q.Set("id", "eq."+storeID)
	if err := h.pr.Update(ctx, "stores", q, map[string]any{"download": body.Download}, nil); err != nil {
		httpx.WritePostgrestErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
