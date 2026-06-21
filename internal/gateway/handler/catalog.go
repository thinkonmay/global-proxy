package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

const catalogQueryTimeout = 5 * time.Second

// CatalogHandler serves public /v1/catalog/* reads (D20 / P1-G).
type CatalogHandler struct {
	pr *postgrest.Client
}

func NewCatalogHandler(pr *postgrest.Client) *CatalogHandler {
	return &CatalogHandler{pr: pr}
}

func (h *CatalogHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/catalog/plans", h.ListPlans)
	mux.HandleFunc("GET /v1/catalog/plans/{planName}", h.GetPlan)
	mux.HandleFunc("GET /v1/catalog/stores", h.ListStores)
	mux.HandleFunc("GET /v1/catalog/stores/{storeID}/depot-keys", h.GetStoreDepotKeys)
	mux.HandleFunc("GET /v1/catalog/stores/{storeID}", h.GetStore)
	mux.HandleFunc("GET /v1/catalog/banners", h.ListBanners)
	mux.HandleFunc("GET /v1/catalog/discounts", h.ListDiscounts)
	mux.HandleFunc("GET /v1/catalog/currency-rates", h.ListCurrencyRates)
	mux.HandleFunc("GET /v1/catalog/app-info", h.AppInfo)
	mux.HandleFunc("GET /v1/catalog/genres", h.ListGenres)
	mux.HandleFunc("GET /v1/catalog/addons", h.ListAddons)
	mux.HandleFunc("GET /v1/catalog/blog", h.ListBlog)
	mux.HandleFunc("GET /v1/catalog/constants", h.ListConstants)
	mux.HandleFunc("GET /v1/catalog/resources", h.ListResources)
	mux.HandleFunc("GET /v1/catalog/binary-releases", h.ListBinaryReleases)
	mux.HandleFunc("GET /v1/catalog/promo-banners", h.ListPromoBanners)
	mux.HandleFunc("GET /v1/search/stores", h.SearchStores)
	mux.HandleFunc("POST /v1/search/stores", h.SearchStoresBatch)
	mux.HandleFunc("POST /v1/search/stores/", h.SearchStoresBatch)
}

func (h *CatalogHandler) ListPlans(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), catalogQueryTimeout)
	defer cancel()

	q := url.Values{}
	q.Set("select", strings.Join([]string{
		"name", "extendable", "total_hours", "total_days", "credit", "active",
		"configuration->max_duration",
		"policy->v4_policy->>CPU",
		"policy->v4_policy->>RAM",
		"policy->v4_policy->>GPU",
		"policy->v4_policy->>DISK",
		"policy->v4_policy->>only_cluster",
		"price->storage",
		"price->allowances",
		"price->VND",
		"price->USD",
		"price->IDR",
	}, ", "))
	q.Set("metadata->v4_hide", "is.null")
	if active := strings.TrimSpace(r.URL.Query().Get("active")); active == "" || active == "true" {
		q.Set("active", "eq.true")
	}
	if cluster := strings.TrimSpace(r.URL.Query().Get("cluster")); cluster != "" {
		q.Set("policy->v4_policy->>only_cluster", "eq."+cluster)
	}

	var rows []map[string]any
	if err := h.pr.Select(ctx, "plans", q, &rows); err != nil {
		writePostgrestErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": rows})
}

func (h *CatalogHandler) GetPlan(w http.ResponseWriter, r *http.Request) {
	planName := strings.TrimSpace(r.PathValue("planName"))
	if planName == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "plan name required"})
		return
	}
	view := strings.TrimSpace(r.URL.Query().Get("view"))
	if view == "" {
		view = "full"
	}

	ctx, cancel := context.WithTimeout(r.Context(), catalogQueryTimeout)
	defer cancel()

	switch view {
	case "policy":
		q := url.Values{}
		q.Set("select", "total_days,disk:configuration->>disk")
		q.Set("active", "eq.true")
		q.Set("name", "eq."+planName)
		q.Set("limit", "1")
		var rows []struct {
			TotalDays *float64 `json:"total_days"`
			Disk      *string  `json:"disk"`
		}
		if err := h.pr.Select(ctx, "plans", q, &rows); err != nil {
			writePostgrestErr(w, err)
			return
		}
		if len(rows) == 0 {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": fmt.Sprintf("plan %s not found", planName)})
			return
		}
		disk := float64(0)
		if rows[0].Disk != nil {
			disk, _ = strconv.ParseFloat(*rows[0].Disk, 64)
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"total_days": rows[0].TotalDays, "disk": disk}})
	case "price":
		currency := strings.TrimSpace(r.URL.Query().Get("currency"))
		if currency == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing currency"})
			return
		}
		q := url.Values{}
		q.Set("select", fmt.Sprintf("price->%s", currency))
		q.Set("active", "eq.true")
		q.Set("name", "eq."+planName)
		q.Set("limit", "1")
		var rows []map[string]json.RawMessage
		if err := h.pr.Select(ctx, "plans", q, &rows); err != nil {
			writePostgrestErr(w, err)
			return
		}
		if len(rows) == 0 {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": fmt.Sprintf("plan %s not found", planName)})
			return
		}
		raw, ok := rows[0][currency]
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "price not found"})
			return
		}
		var val map[string]any
		if err := json.Unmarshal(raw, &val); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": val})
	case "credit":
		q := url.Values{}
		q.Set("select", "credit,name")
		q.Set("active", "eq.true")
		q.Set("name", "eq."+planName)
		q.Set("limit", "1")
		var rows []map[string]any
		if err := h.pr.Select(ctx, "plans", q, &rows); err != nil {
			writePostgrestErr(w, err)
			return
		}
		if len(rows) == 0 {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": fmt.Sprintf("plan %s not found", planName)})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": rows[0]})
	default:
		q := url.Values{}
		q.Set("select", strings.Join([]string{
			"name", "extendable", "total_hours", "total_days", "credit",
			"configuration->max_duration",
			"policy->v4_policy->>CPU",
			"policy->v4_policy->>RAM",
			"policy->v4_policy->>GPU",
			"policy->v4_policy->>DISK",
			"policy->v4_policy->>only_cluster",
			"price->storage",
			"price->allowances",
			"price->VND",
			"price->USD",
			"price->IDR",
		}, ", "))
		q.Set("name", "eq."+planName)
		q.Set("limit", "1")
		var rows []map[string]any
		if err := h.pr.Select(ctx, "plans", q, &rows); err != nil {
			writePostgrestErr(w, err)
			return
		}
		if len(rows) == 0 {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": fmt.Sprintf("plan %s not found", planName)})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": rows[0]})
	}
}

func (h *CatalogHandler) ListStores(w http.ResponseWriter, r *http.Request) {
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
	selectCols := "id,name,code_name,type,created_at,metadata->>short_description,metadata->>header_image,queue,genres"
	if detail == "full" {
		selectCols = strings.Join([]string{
			"id", "name", "code_name", "type", "created_at",
			"metadata->publishers",
			"metadata->support_info",
			"metadata->short_description",
			"metadata->detailed_description",
			"metadata->>header_image",
			"metadata->pc_requirements",
			"metadata->screenshots",
			"download",
			"queue",
			"genres",
		}, ",")
	}

	q := url.Values{}
	q.Set("select", selectCols)
	q.Set("metadata", "not.is.null")
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
		writePostgrestErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": rows})
}

func (h *CatalogHandler) GetStore(w http.ResponseWriter, r *http.Request) {
	storeID := strings.TrimSpace(r.PathValue("storeID"))
	if storeID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "store id required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), catalogQueryTimeout)
	defer cancel()

	q := url.Values{}
	q.Set("select", strings.Join([]string{
		"id", "name", "code_name", "type",
		"metadata->publishers",
		"metadata->support_info",
		"metadata->short_description",
		"metadata->detailed_description",
		"metadata->>header_image",
		"metadata->pc_requirements",
		"metadata->screenshots",
		"download",
		"queue",
		"genres",
	}, ","))
	q.Set("id", "eq."+storeID)
	q.Set("limit", "1")

	var rows []map[string]any
	if err := h.pr.Select(ctx, "stores", q, &rows); err != nil {
		writePostgrestErr(w, err)
		return
	}
	if len(rows) == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "store not found"})
		return
	}
	writeJSON(w, http.StatusOK, rows[0])
}

func (h *CatalogHandler) GetStoreDepotKeys(w http.ResponseWriter, r *http.Request) {
	storeID := strings.TrimSpace(r.PathValue("storeID"))
	id, err := strconv.ParseInt(storeID, 10, 64)
	if storeID == "" || err != nil || id <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "store id required"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), catalogQueryTimeout)
	defer cancel()

	var out json.RawMessage
	if err := h.pr.RPC(ctx, "get_depotkey", map[string]any{"app_id": id}, &out); err != nil {
		writePostgrestErr(w, err)
		return
	}
	if len(out) == 0 || string(out) == "null" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "depot keys not found"})
		return
	}

	var keys map[string]string
	if err := json.Unmarshal(out, &keys); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if len(keys) == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "depot keys not found"})
		return
	}
	writeJSON(w, http.StatusOK, keys)
}

func (h *CatalogHandler) ListBanners(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), catalogQueryTimeout)
	defer cancel()
	q := url.Values{}
	q.Set("select", "url,alt")
	q.Set("active", "eq.true")
	q.Set("order", "priority.desc")
	var rows []map[string]any
	if err := h.pr.Select(ctx, "banner", q, &rows); err != nil {
		writePostgrestErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": rows})
}

func (h *CatalogHandler) ListDiscounts(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), catalogQueryTimeout)
	defer cancel()
	q := url.Values{}
	q.Set("select", "code,start_at,end_at,discount_limit_per_user,discount_limit,multiply_rate,apply_for")
	var rows []map[string]any
	if err := h.pr.Select(ctx, "discounts", q, &rows); err != nil {
		writePostgrestErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": rows})
}

func (h *CatalogHandler) ListCurrencyRates(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), catalogQueryTimeout)
	defer cancel()
	q := url.Values{}
	q.Set("select", "currency,rate_to_system_credit,is_base")
	var rows []map[string]any
	if err := h.pr.Select(ctx, "currency_rates", q, &rows); err != nil {
		writePostgrestErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": rows})
}

func (h *CatalogHandler) AppInfo(w http.ResponseWriter, r *http.Request) {
	appID := strings.TrimSpace(r.URL.Query().Get("id"))
	if appID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), catalogQueryTimeout)
	defer cancel()
	q := url.Values{}
	q.Set("select", "name,header_image:metadata->>header_image")
	q.Set("id", "eq."+appID)
	q.Set("limit", "1")
	var rows []struct {
		Name        string  `json:"name"`
		HeaderImage *string `json:"header_image"`
	}
	if err := h.pr.Select(ctx, "stores", q, &rows); err != nil {
		writeJSON(w, http.StatusOK, nil)
		return
	}
	if len(rows) == 0 {
		writeJSON(w, http.StatusOK, nil)
		return
	}
	image := ""
	if rows[0].HeaderImage != nil {
		image = *rows[0].HeaderImage
	}
	writeJSON(w, http.StatusOK, map[string]string{"name": rows[0].Name, "image": image})
}

func (h *CatalogHandler) ListGenres(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), catalogQueryTimeout)
	defer cancel()
	var rows []map[string]any
	if err := h.pr.RPC(ctx, "get_all_app_genres_v1", map[string]any{}, &rows); err != nil {
		writePostgrestErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": rows})
}

func (h *CatalogHandler) ListAddons(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), catalogQueryTimeout)
	defer cancel()
	q := url.Values{}
	q.Set("select", "id,name,unit_type,unit_price")
	q.Set("active", "eq.true")
	var rows []map[string]any
	if err := h.pr.Select(ctx, "addons", q, &rows); err != nil {
		writePostgrestErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": rows})
}

func (h *CatalogHandler) ListBlog(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), catalogQueryTimeout)
	defer cancel()
	q := url.Values{}
	q.Set("select", "*")
	if slug := strings.TrimSpace(r.URL.Query().Get("slug")); slug != "" {
		q.Set("slug", "eq."+slug)
		q.Set("limit", "1")
	} else {
		q.Set("order", "created_at.desc")
		if limit := strings.TrimSpace(r.URL.Query().Get("limit")); limit != "" {
			q.Set("limit", limit)
		}
	}
	var rows []map[string]any
	if err := h.pr.Select(ctx, "blog", q, &rows); err != nil {
		writePostgrestErr(w, err)
		return
	}
	if slug := strings.TrimSpace(r.URL.Query().Get("slug")); slug != "" {
		if len(rows) == 0 {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		writeJSON(w, http.StatusOK, rows[0])
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": rows})
}

func (h *CatalogHandler) ListConstants(w http.ResponseWriter, r *http.Request) {
	names := strings.TrimSpace(r.URL.Query().Get("names"))
	if names == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "names query required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), catalogQueryTimeout)
	defer cancel()
	parts := strings.Split(names, ",")
	quoted := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			quoted = append(quoted, fmt.Sprintf("%q", p))
		}
	}
	q := url.Values{}
	q.Set("select", "name,value")
	q.Set("name", "in.("+strings.Join(quoted, ",")+")")
	var rows []map[string]any
	if err := h.pr.Select(ctx, "constant", q, &rows); err != nil {
		writePostgrestErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": rows})
}

func (h *CatalogHandler) ListResources(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), catalogQueryTimeout)
	defer cancel()
	q := url.Values{}
	q.Set("select", "daily_price,name,configuration,type")
	q.Set("active", "eq.true")
	var rows []map[string]any
	if err := h.pr.Select(ctx, "resources", q, &rows); err != nil {
		writePostgrestErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": rows})
}

func (h *CatalogHandler) ListBinaryReleases(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), catalogQueryTimeout)
	defer cancel()
	q := url.Values{}
	q.Set("select", "name,download_url,md5sum,created_at,updated,channel")
	if channel := strings.TrimSpace(r.URL.Query().Get("channel")); channel != "" {
		q.Set("channel", "eq."+channel)
	}
	if names := strings.TrimSpace(r.URL.Query().Get("names")); names != "" {
		parts := strings.Split(names, ",")
		quoted := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				quoted = append(quoted, fmt.Sprintf("%q", p))
			}
		}
		if len(quoted) > 0 {
			q.Set("name", "in.("+strings.Join(quoted, ",")+")")
		}
	}
	q.Set("order", "created_at.desc")
	var rows []map[string]any
	if err := h.pr.Select(ctx, "binary_release", q, &rows); err != nil {
		writePostgrestErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": rows})
}

func (h *CatalogHandler) SearchStores(w http.ResponseWriter, r *http.Request) {
	text := strings.TrimSpace(r.URL.Query().Get("q"))
	if text == "" {
		text = strings.TrimSpace(r.URL.Query().Get("text"))
	}
	if text == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "q required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), catalogQueryTimeout)
	defer cancel()
	var rows []map[string]any
	if err := h.pr.RPC(ctx, "search_stores", map[string]any{"text": text}, &rows); err != nil {
		writePostgrestErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": rows})
}

func (h *CatalogHandler) ListPromoBanners(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), catalogQueryTimeout)
	defer cancel()
	var rows []map[string]any
	if err := h.pr.RPC(ctx, "get_banner_v1", map[string]any{}, &rows); err != nil {
		writePostgrestErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": rows})
}

func (h *CatalogHandler) SearchStoresBatch(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Texts []string `json:"texts"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "texts required"})
		return
	}
	texts := make([]string, 0, len(body.Texts))
	for _, text := range body.Texts {
		if t := strings.TrimSpace(text); t != "" {
			texts = append(texts, t)
		}
	}
	if len(texts) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"data": []any{}})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), catalogQueryTimeout)
	defer cancel()
	var rows []map[string]any
	if err := h.pr.RPC(ctx, "search_stores", map[string]any{"texts": texts}, &rows); err != nil {
		writePostgrestErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": rows})
}
