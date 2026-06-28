package pwa

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/auth"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/httpx"
)

func (h *Handler) AppInfo(w http.ResponseWriter, r *http.Request) {
	appID := strings.TrimSpace(r.PathValue("appID"))
	if appID == "" {
		httpx.WriteJSON(w, http.StatusBadRequest, nil)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), pwaQueryTimeout)
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

func (h *Handler) CurrencyRates(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), pwaQueryTimeout)
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

func (h *Handler) PlansCredit(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), pwaQueryTimeout)
	defer cancel()
	q := url.Values{}
	q.Set("select", "credit,name")
	q.Set("active", "eq.true")
	var rows []map[string]any
	if err := h.pr.Select(ctx, "plans", q, &rows); err != nil {
		httpx.WriteError(w, http.StatusOK, err.Error())
		return
	}
	if len(rows) == 0 {
		httpx.WriteError(w, http.StatusOK, "no plan available")
		return
	}
	httpx.WriteData(w, rows)
}

func (h *Handler) PlanPolicy(w http.ResponseWriter, r *http.Request) {
	planName := strings.TrimSpace(r.PathValue("planName"))
	if planName == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid type")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), pwaQueryTimeout)
	defer cancel()
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
		httpx.WriteError(w, http.StatusOK, err.Error())
		return
	}
	if len(rows) == 0 {
		httpx.WriteError(w, http.StatusOK, fmt.Sprintf("plan %s not found", planName))
		return
	}
	disk := float64(0)
	if rows[0].Disk != nil {
		disk, _ = strconv.ParseFloat(*rows[0].Disk, 64)
	}
	httpx.WriteData(w, map[string]any{"total_days": rows[0].TotalDays, "disk": disk})
}

func (h *Handler) PlanPrice(w http.ResponseWriter, r *http.Request) {
	planName := strings.TrimSpace(r.PathValue("planName"))
	currency := strings.TrimSpace(r.URL.Query().Get("currency"))
	if planName == "" || currency == "" {
		httpx.WriteError(w, http.StatusBadRequest, "missing currency")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), pwaQueryTimeout)
	defer cancel()
	q := url.Values{}
	q.Set("select", fmt.Sprintf("price->%s", currency))
	q.Set("active", "eq.true")
	q.Set("name", "eq."+planName)
	q.Set("limit", "1")
	var rows []map[string]json.RawMessage
	if err := h.pr.Select(ctx, "plans", q, &rows); err != nil {
		httpx.WriteError(w, http.StatusOK, err.Error())
		return
	}
	if len(rows) == 0 {
		httpx.WriteError(w, http.StatusOK, fmt.Sprintf("plan %s not found", planName))
		return
	}
	raw, ok := rows[0][currency]
	if !ok || len(raw) == 0 || string(raw) == "null" {
		httpx.WriteError(w, http.StatusOK, "price not found")
		return
	}
	var amount float64
	if err := json.Unmarshal(raw, &amount); err != nil {
		httpx.WriteError(w, http.StatusOK, err.Error())
		return
	}
	httpx.WriteData(w, amount)
}

func (h *Handler) Feedback(w http.ResponseWriter, r *http.Request) {
	var args map[string]any
	if err := httpx.ReadJSONBody(r, &args); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), pwaQueryTimeout)
	defer cancel()
	if err := h.pr.Insert(ctx, "feedbacks", args, nil); err != nil {
		httpx.WritePostgrestErr(w, err)
		return
	}
	httpx.WriteData(w, nil)
}

func (h *Handler) Referrals(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := httpx.ReadJSONBody(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Email == "" {
		httpx.WriteError(w, http.StatusBadRequest, "Missing email")
		return
	}
	usr, code, msg := auth.PWAAuthFromRequest(r.Context(), h.transport, r)
	if code != 0 {
		httpx.WriteError(w, code, msg)
		return
	}
	if c, m := auth.PWAEmailMatch(usr, req.Email); c != 0 {
		httpx.WriteError(w, c, m)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), pwaQueryTimeout)
	defer cancel()

	q := url.Values{}
	q.Set("select", "to,created_at")
	q.Set("from", "eq."+req.Email)
	q.Set("to", "neq."+req.Email)
	q.Set("order", "created_at.desc")
	var referrals []struct {
		To string `json:"to"`
	}
	if err := h.pr.Select(ctx, "referral", q, &referrals); err != nil || len(referrals) == 0 {
		httpx.WriteData(w, []any{})
		return
	}
	seen := make(map[string]struct{})
	referred := make([]string, 0, len(referrals))
	for _, row := range referrals {
		if row.To == "" {
			continue
		}
		if _, ok := seen[row.To]; ok {
			continue
		}
		seen[row.To] = struct{}{}
		referred = append(referred, row.To)
	}
	if len(referred) == 0 {
		httpx.WriteData(w, []any{})
		return
	}

	paid := make(map[string]struct{})
	payQ := url.Values{}
	payQ.Set("select", "subscription!inner(user)")
	payQ.Set("subscription.user", "in.("+quoteInFilter(referred)+")")
	payQ.Set("verified_at", "not.is.null")
	var payments []struct {
		Subscription struct {
			User string `json:"user"`
		} `json:"subscription"`
	}
	_ = h.pr.Select(ctx, "entitlements", payQ, &payments)
	for _, p := range payments {
		if p.Subscription.User != "" {
			paid[p.Subscription.User] = struct{}{}
		}
	}

	userMap := map[string]struct {
		Username string
		Avatar   string
	}{}
	userQ := url.Values{}
	userQ.Set("select", "email,metadata")
	userQ.Set("email", "in.("+quoteInFilter(referred)+")")
	var userRows []struct {
		Email    string          `json:"email"`
		Metadata json.RawMessage `json:"metadata"`
	}
	if err := h.pr.SelectService(ctx, "users", userQ, &userRows); err == nil {
		for _, u := range userRows {
			var meta struct {
				Name   string `json:"name"`
				Avatar string `json:"avatar"`
			}
			if len(u.Metadata) > 0 {
				_ = json.Unmarshal(u.Metadata, &meta)
			}
			avatar := meta.Avatar
			if avatar == "" {
				avatar = fmt.Sprintf("https://api.dicebear.com/9.x/thumbs/svg?seed=%s", u.Email)
			}
			userMap[u.Email] = struct {
				Username string
				Avatar   string
			}{
				Username: meta.Name,
				Avatar:   avatar,
			}
		}
	}

	out := make([]map[string]any, 0, len(referred))
	for _, e := range referred {
		info := userMap[e]
		username := info.Username
		if username == "" {
			username = strings.Split(e, "@")[0]
		}
		_, hasPaid := paid[e]
		out = append(out, map[string]any{
			"email":    e,
			"username": username,
			"avatar":   info.Avatar,
			"hasPaid":  hasPaid,
		})
	}
	httpx.WriteData(w, out)
}
