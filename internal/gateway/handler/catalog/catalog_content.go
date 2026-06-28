package catalog

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/httpx"
)

func (h *Handler) ListBanners(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), catalogQueryTimeout)
	defer cancel()
	q := url.Values{}
	q.Set("select", "url,alt")
	q.Set("active", "eq.true")
	q.Set("order", "priority.desc")
	var rows []map[string]any
	if err := h.pr.Select(ctx, "banner", q, &rows); err != nil {
		httpx.WritePostgrestErr(w, err)
		return
	}
	httpx.WriteData(w, rows)
}

func (h *Handler) ListDiscounts(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), catalogQueryTimeout)
	defer cancel()
	q := url.Values{}
	q.Set("select", "code,start_at,end_at,discount_limit_per_user,discount_limit,multiply_rate,apply_for")
	var rows []map[string]any
	if err := h.pr.Select(ctx, "discounts", q, &rows); err != nil {
		httpx.WritePostgrestErr(w, err)
		return
	}
	httpx.WriteData(w, rows)
}

func (h *Handler) ListCurrencyRates(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), catalogQueryTimeout)
	defer cancel()
	q := url.Values{}
	q.Set("select", "currency,rate_to_system_credit,is_base")
	var rows []map[string]any
	if err := h.pr.Select(ctx, "currency_rates", q, &rows); err != nil {
		httpx.WritePostgrestErr(w, err)
		return
	}
	httpx.WriteData(w, rows)
}

func (h *Handler) AppInfo(w http.ResponseWriter, r *http.Request) {
	appID := strings.TrimSpace(r.PathValue("appID"))
	if appID == "" {
		httpx.WriteError(w, http.StatusBadRequest, "id required")
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
		httpx.WriteJSON(w, http.StatusOK, nil)
		return
	}
	if len(rows) == 0 {
		httpx.WriteJSON(w, http.StatusOK, nil)
		return
	}
	image := ""
	if rows[0].HeaderImage != nil {
		image = *rows[0].HeaderImage
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"name": rows[0].Name, "image": image})
}

func (h *Handler) ListGenres(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), catalogQueryTimeout)
	defer cancel()
	var rows []map[string]any
	if err := h.pr.RPC(ctx, "get_all_app_genres_v1", map[string]any{}, &rows); err != nil {
		httpx.WritePostgrestErr(w, err)
		return
	}
	httpx.WriteData(w, rows)
}

func (h *Handler) ListAddons(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), catalogQueryTimeout)
	defer cancel()
	q := url.Values{}
	q.Set("select", "id,name,unit_type,unit_price")
	q.Set("active", "eq.true")
	var rows []map[string]any
	if err := h.pr.Select(ctx, "addons", q, &rows); err != nil {
		httpx.WritePostgrestErr(w, err)
		return
	}
	httpx.WriteData(w, rows)
}

func (h *Handler) ListBlog(w http.ResponseWriter, r *http.Request) {
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
		httpx.WritePostgrestErr(w, err)
		return
	}
	if slug := strings.TrimSpace(r.URL.Query().Get("slug")); slug != "" {
		if len(rows) == 0 {
			httpx.WriteError(w, http.StatusNotFound, "not found")
			return
		}
		httpx.WriteJSON(w, http.StatusOK, rows[0])
		return
	}
	httpx.WriteData(w, rows)
}

func (h *Handler) ListConstants(w http.ResponseWriter, r *http.Request) {
	names := strings.TrimSpace(r.URL.Query().Get("names"))
	if names == "" {
		httpx.WriteError(w, http.StatusBadRequest, "names query required")
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
		httpx.WritePostgrestErr(w, err)
		return
	}
	httpx.WriteData(w, rows)
}

func (h *Handler) ListResources(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), catalogQueryTimeout)
	defer cancel()
	q := url.Values{}
	q.Set("select", "daily_price,name,configuration,type")
	q.Set("active", "eq.true")
	var rows []map[string]any
	if err := h.pr.Select(ctx, "resources", q, &rows); err != nil {
		httpx.WritePostgrestErr(w, err)
		return
	}
	httpx.WriteData(w, rows)
}

func (h *Handler) ListBinaryReleases(w http.ResponseWriter, r *http.Request) {
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
		httpx.WritePostgrestErr(w, err)
		return
	}
	httpx.WriteData(w, rows)
}
