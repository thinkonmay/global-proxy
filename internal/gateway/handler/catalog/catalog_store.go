package catalog

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/httpx"
	"github.com/thinkonmay/global-proxy/api/pkg/storeindex"
)

func (h *Handler) ListStores(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), catalogQueryTimeout)
	defer cancel()

	limit := 50
	if v := strings.TrimSpace(r.URL.Query().Get("limit")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 {
			limit = n
		}
	}
	offset := 0
	if v := strings.TrimSpace(r.URL.Query().Get("offset")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}

	detail := strings.TrimSpace(r.URL.Query().Get("detail"))
	selectCols := "id,name,code_name,type,created_at,short_description,header_image,queue,genres"
	if detail == "full" {
		selectCols = strings.Join([]string{
			"id", "name", "code_name", "type", "created_at",
			"short_description", "header_image",
			"download", "queue", "genres", "benchmarks",
		}, ",")
	}

	q := url.Values{}
	q.Set("select", selectCols)
	q.Set("header_image", "not.is.null")
	q.Set("order", "priority")
	q.Set("limit", strconv.Itoa(limit))
	q.Set("offset", strconv.Itoa(offset))
	if genre := strings.TrimSpace(r.URL.Query().Get("genre")); genre != "" {
		q.Set("genres", "cs.{"+genre+"}")
	}
	if codeName := strings.TrimSpace(r.URL.Query().Get("code_name")); codeName != "" {
		q.Set("code_name", "eq."+codeName)
	}
	if strings.TrimSpace(r.URL.Query().Get("has_download")) == "true" {
		q.Set("download", "not.is.null")
	}

	var rows []map[string]any
	if err := h.pr.Select(ctx, "stores", q, &rows); err != nil {
		httpx.WritePostgrestErr(w, err)
		return
	}
	if detail == "full" && h.stores != nil && h.stores.Enabled() {
		for i := range rows {
			h.mergeStoreDetail(ctx, rows[i])
		}
	}
	httpx.WriteData(w, rows)
}

func (h *Handler) GetStore(w http.ResponseWriter, r *http.Request) {
	storeID := strings.TrimSpace(r.PathValue("storeID"))
	if storeID == "" {
		httpx.WriteError(w, http.StatusBadRequest, "store id required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), catalogQueryTimeout)
	defer cancel()

	q := url.Values{}
	q.Set("select", strings.Join([]string{
		"id", "name", "code_name", "type", "short_description", "header_image",
		"download", "queue", "genres", "benchmarks",
	}, ","))
	q.Set("id", "eq."+storeID)
	q.Set("limit", "1")

	var rows []map[string]any
	if err := h.pr.Select(ctx, "stores", q, &rows); err != nil {
		httpx.WritePostgrestErr(w, err)
		return
	}
	if len(rows) == 0 {
		httpx.WriteError(w, http.StatusNotFound, "store not found")
		return
	}
	h.mergeStoreDetail(ctx, rows[0])
	httpx.WriteJSON(w, http.StatusOK, rows[0])
}

func (h *Handler) mergeStoreDetail(ctx context.Context, row map[string]any) {
	if h.stores == nil || !h.stores.Enabled() || row == nil {
		return
	}
	id, ok := parseStoreID(row["id"])
	if !ok {
		return
	}
	doc, err := h.stores.Get(ctx, id)
	if err != nil || doc == nil || doc.Metadata == nil {
		return
	}
	meta := doc.Metadata
	row["publishers"] = meta["publishers"]
	row["support_info"] = meta["support_info"]
	row["detailed_description"] = meta["detailed_description"]
	row["pc_requirements"] = meta["pc_requirements"]
	row["screenshots"] = meta["screenshots"]
	row["metadata_locale"] = doc.MetadataLocale
	if v, ok := meta["short_description"].(string); ok && v != "" {
		row["short_description"] = v
	}
	if v, ok := meta["header_image"].(string); ok && v != "" {
		row["header_image"] = v
	}
}

func parseStoreID(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), n > 0
	case int64:
		return n, n > 0
	case json.Number:
		i, err := n.Int64()
		return i, err == nil && i > 0
	case string:
		i, err := strconv.ParseInt(n, 10, 64)
		return i, err == nil && i > 0
	default:
		return 0, false
	}
}

func (h *Handler) GetStoreDepotKeys(w http.ResponseWriter, r *http.Request) {
	storeID := strings.TrimSpace(r.PathValue("storeID"))
	id, err := strconv.ParseInt(storeID, 10, 64)
	if storeID == "" || err != nil || id <= 0 {
		httpx.WriteError(w, http.StatusBadRequest, "store id required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), catalogQueryTimeout)
	defer cancel()

	var out json.RawMessage
	if err := h.pr.RPC(ctx, "get_depotkey", map[string]any{"app_id": id}, &out); err != nil {
		httpx.WritePostgrestErr(w, err)
		return
	}
	if len(out) == 0 || string(out) == "null" {
		httpx.WriteError(w, http.StatusNotFound, "depot keys not found")
		return
	}

	var keys map[string]string
	if err := json.Unmarshal(out, &keys); err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if len(keys) == 0 {
		httpx.WriteError(w, http.StatusNotFound, "depot keys not found")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, keys)
}

func (h *Handler) SearchStores(w http.ResponseWriter, r *http.Request) {
	text := strings.TrimSpace(r.URL.Query().Get("q"))
	if text == "" {
		text = strings.TrimSpace(r.URL.Query().Get("text"))
	}
	if text == "" {
		httpx.WriteError(w, http.StatusBadRequest, "q required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), catalogQueryTimeout)
	defer cancel()

	if h.stores != nil && h.stores.Enabled() {
		hits, err := h.stores.Search(ctx, text, 20)
		if err != nil {
			httpx.WriteError(w, http.StatusServiceUnavailable, "search unavailable")
			return
		}
		httpx.WriteData(w, searchHitsToMaps(hits))
		return
	}

	var rows []map[string]any
	if err := h.pr.RPC(ctx, "search_stores", map[string]any{"text": text}, &rows); err != nil {
		httpx.WritePostgrestErr(w, err)
		return
	}
	httpx.WriteData(w, rows)
}

func (h *Handler) SearchStoresBatch(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Texts []string `json:"texts"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "texts required")
		return
	}
	texts := make([]string, 0, len(body.Texts))
	for _, text := range body.Texts {
		if t := strings.TrimSpace(text); t != "" {
			texts = append(texts, t)
		}
	}
	if len(texts) == 0 {
		httpx.WriteData(w, []any{})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), catalogQueryTimeout)
	defer cancel()

	if h.stores != nil && h.stores.Enabled() {
		hits, err := h.stores.SearchBatch(ctx, texts)
		if err != nil {
			httpx.WriteError(w, http.StatusServiceUnavailable, "search unavailable")
			return
		}
		httpx.WriteData(w, searchHitsToMaps(hits))
		return
	}

	var rows []map[string]any
	if err := h.pr.RPC(ctx, "search_stores", map[string]any{"texts": texts}, &rows); err != nil {
		httpx.WritePostgrestErr(w, err)
		return
	}
	httpx.WriteData(w, rows)
}

func searchHitsToMaps(hits []storeindex.SearchHit) []map[string]any {
	out := make([]map[string]any, 0, len(hits))
	for _, hit := range hits {
		out = append(out, map[string]any{
			"id":                   hit.ID,
			"name":                 hit.Name,
			"code_name":            hit.CodeName,
			"publishers":           hit.Publishers,
			"support_info":         hit.SupportInfo,
			"short_description":    hit.ShortDescription,
			"detailed_description": hit.DetailedDescription,
			"header_image":         hit.HeaderImage,
			"pc_requirements":      hit.PCRequirements,
			"screenshots":            hit.Screenshots,
			"genres":               hit.Genres,
			"type":                 hit.Type,
			"queue":                hit.Queue,
			"benchmarks":           hit.Benchmarks,
			"metadata_locale":      hit.MetadataLocale,
			"rank":                 hit.Rank,
		})
	}
	return out
}

func (h *Handler) ListPromoBanners(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), catalogQueryTimeout)
	defer cancel()
	var rows []map[string]any
	if err := h.pr.RPC(ctx, "get_banner_v1", map[string]any{}, &rows); err != nil {
		httpx.WritePostgrestErr(w, err)
		return
	}
	httpx.WriteData(w, rows)
}
