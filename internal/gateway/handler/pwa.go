package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/pkg/pocketbase"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

const pwaQueryTimeout = 5 * time.Second

// PWAHandler serves browser PWA API routes (replaces website/app/api/*).
type PWAHandler struct {
	pr         *postgrest.Client
	pbAdmin    *pocketbase.Client
	pbURL      string
	persona    *PersonaHandler
	llm        config.LLM
	httpClient *http.Client
	transport  http.RoundTripper
}

func NewPWAHandler(cfg config.Config, pr *postgrest.Client, rt http.RoundTripper, persona *PersonaHandler) *PWAHandler {
	if rt == nil {
		rt = http.DefaultTransport
	}
	return &PWAHandler{
		pr:      pr,
		pbURL:   strings.TrimRight(cfg.PocketBase.URL, "/"),
		pbAdmin: pocketbase.New(pocketbase.Config{URL: cfg.PocketBase.URL, Username: cfg.PocketBase.Username, Password: cfg.PocketBase.Password, Transport: rt}),
		persona: persona,
		llm:     cfg.LLM,
		httpClient: &http.Client{
			Timeout:   60 * time.Second,
			Transport: rt,
		},
		transport: rt,
	}
}

// Register mounts PWA endpoints under /api/pwa/* and legacy /api/* aliases.
func (h *PWAHandler) Register(mux *http.ServeMux) {
	routes := []struct {
		method string
		path   string
		fn     http.HandlerFunc
	}{
		{http.MethodGet, "/app_info", h.AppInfo},
		{http.MethodGet, "/currency_rates", h.CurrencyRates},
		{http.MethodGet, "/plans", h.Plans},
		{http.MethodPost, "/feedback", h.Feedback},
		{http.MethodPost, "/referrals", h.Referrals},
		{http.MethodPost, "/is_superuser", h.IsSuperuser},
		{http.MethodPost, "/update_code_name", h.UpdateCodeName},
		{http.MethodPost, "/search", h.Search},
		{http.MethodGet, "/persona/recommendations", h.persona.GetRecommendations},
	}
	for _, route := range routes {
		pwaPath := "/api/pwa" + route.path
		legacyPath := "/api" + route.path
		mux.HandleFunc(route.method+" "+pwaPath, route.fn)
		mux.HandleFunc(route.method+" "+pwaPath+"/", route.fn)
		mux.HandleFunc(route.method+" "+legacyPath, route.fn)
		mux.HandleFunc(route.method+" "+legacyPath+"/", route.fn)
	}
}

func (h *PWAHandler) AppInfo(w http.ResponseWriter, r *http.Request) {
	appID := strings.TrimSpace(r.URL.Query().Get("id"))
	if appID == "" {
		writeJSON(w, http.StatusBadRequest, nil)
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

func (h *PWAHandler) CurrencyRates(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), pwaQueryTimeout)
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

func (h *PWAHandler) Plans(w http.ResponseWriter, r *http.Request) {
	typ := strings.TrimSpace(r.URL.Query().Get("type"))
	planName := strings.TrimSpace(r.URL.Query().Get("plan_name"))
	ctx, cancel := context.WithTimeout(r.Context(), pwaQueryTimeout)
	defer cancel()

	switch typ {
	case "policy":
		if planName == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid type"})
			return
		}
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
			writeJSON(w, http.StatusOK, map[string]string{"error": err.Error()})
			return
		}
		if len(rows) == 0 {
			writeJSON(w, http.StatusOK, map[string]string{"error": fmt.Sprintf("plan %s not found", planName)})
			return
		}
		disk := float64(0)
		if rows[0].Disk != nil {
			disk, _ = strconv.ParseFloat(*rows[0].Disk, 64)
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"total_days": rows[0].TotalDays, "disk": disk}})
	case "price":
		currency := strings.TrimSpace(r.URL.Query().Get("currency"))
		if planName == "" || currency == "" {
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
			writeJSON(w, http.StatusOK, map[string]string{"error": err.Error()})
			return
		}
		if len(rows) == 0 {
			writeJSON(w, http.StatusOK, map[string]string{"error": fmt.Sprintf("plan %s not found", planName)})
			return
		}
		raw, ok := rows[0][currency]
		if !ok {
			writeJSON(w, http.StatusOK, map[string]string{"error": "price not found"})
			return
		}
		var val map[string]any
		if err := json.Unmarshal(raw, &val); err != nil {
			writeJSON(w, http.StatusOK, map[string]string{"error": err.Error()})
			return
		}
		if amount, ok := val["amount"].(float64); ok {
			val["amount"] = amount
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": val})
	case "credit":
		q := url.Values{}
		q.Set("select", "credit,name")
		q.Set("active", "eq.true")
		var rows []map[string]any
		if err := h.pr.Select(ctx, "plans", q, &rows); err != nil {
			writeJSON(w, http.StatusOK, map[string]string{"error": err.Error()})
			return
		}
		if len(rows) == 0 {
			writeJSON(w, http.StatusOK, map[string]string{"error": "no plan available"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": rows})
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid type"})
	}
}

func (h *PWAHandler) Feedback(w http.ResponseWriter, r *http.Request) {
	var args map[string]any
	if err := readJSONBody(r, &args); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), pwaQueryTimeout)
	defer cancel()
	if err := h.pr.Insert(ctx, "feedbacks", args, nil); err != nil {
		writePostgrestErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": nil})
}

func (h *PWAHandler) Referrals(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email  string `json:"email"`
		Issuer string `json:"issuer"`
	}
	if err := readJSONBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if req.Email == "" || req.Issuer == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Missing email or issuer"})
		return
	}
	auth, code, msg := pwaAuthFromRequest(r.Context(), h.transport, r, req.Issuer)
	if code != 0 {
		writeJSON(w, code, map[string]string{"error": msg})
		return
	}
	if c, m := pwaAuthEmailMatch(auth, req.Email); c != 0 {
		writeJSON(w, c, map[string]string{"error": m})
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
		writeJSON(w, http.StatusOK, map[string]any{"data": []any{}})
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
		writeJSON(w, http.StatusOK, map[string]any{"data": []any{}})
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
	_ = h.pr.Select(ctx, "payment_request", payQ, &payments)
	for _, p := range payments {
		if p.Subscription.User != "" {
			paid[p.Subscription.User] = struct{}{}
		}
	}

	userMap := map[string]struct {
		Username string
		Avatar   string
	}{}
	if h.pbAdmin.Configured() {
		filterParts := make([]string, 0, len(referred))
		for _, e := range referred {
			filterParts = append(filterParts, fmt.Sprintf(`email=%q`, e))
		}
		uq := url.Values{}
		uq.Set("filter", strings.Join(filterParts, " || "))
		uq.Set("fields", "id,email,avatar,collectionId,username,name")
		uq.Set("perPage", "500")
		var page struct {
			Items []struct {
				ID           string `json:"id"`
				Email        string `json:"email"`
				Avatar       string `json:"avatar"`
				CollectionID string `json:"collectionId"`
				Username     string `json:"username"`
				Name         string `json:"name"`
			} `json:"items"`
		}
		if err := h.pbAdmin.ListRecords(ctx, "users", uq, &page); err == nil {
			for _, u := range page.Items {
				name := u.Username
				if name == "" {
					name = u.Name
				}
				userMap[u.Email] = struct {
					Username string
					Avatar   string
				}{
					Username: name,
					Avatar:   pbFileURL(h.pbURL, u.CollectionID, u.ID, u.Avatar),
				}
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
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}

func (h *PWAHandler) IsSuperuser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email  string `json:"email"`
		Issuer string `json:"issuer"`
	}
	if err := readJSONBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if req.Email == "" || req.Issuer == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Missing email or issuer"})
		return
	}
	auth, code, msg := pwaAuthFromRequest(r.Context(), h.transport, r, req.Issuer)
	if code != 0 {
		writeJSON(w, code, map[string]string{"error": msg})
		return
	}
	if c, m := pwaAuthEmailMatch(auth, req.Email); c != 0 {
		writeJSON(w, c, map[string]string{"error": m})
		return
	}
	ok, err := h.isSuperuserEmail(r.Context(), req.Email)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"isSuperuser": ok})
}

func (h *PWAHandler) UpdateCodeName(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AppID    json.Number `json:"app_id"`
		CodeName string      `json:"code_name"`
		Issuer   string      `json:"issuer"`
	}
	if err := readJSONBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if req.CodeName == "" || req.Issuer == "" || req.AppID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Missing app_id, code_name, or issuer"})
		return
	}
	auth, code, msg := pwaAuthFromRequest(r.Context(), h.transport, r, req.Issuer)
	if code != 0 {
		writeJSON(w, code, map[string]string{"error": msg})
		return
	}
	ok, err := h.isSuperuserEmail(r.Context(), auth.Email)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !ok {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "Unauthorized: Not a superuser"})
		return
	}

	sanitized := sanitizeCodeName(req.CodeName)
	ctx, cancel := context.WithTimeout(r.Context(), pwaQueryTimeout)
	defer cancel()
	q := url.Values{}
	q.Set("id", "eq."+req.AppID.String())
	if err := h.pr.Update(ctx, "stores", q, map[string]any{"code_name": sanitized}, nil); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "code_name": sanitized})
}

func sanitizeCodeName(raw string) string {
	s := strings.ToLower(raw)
	var b strings.Builder
	lastUnderscore := false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastUnderscore = false
			continue
		}
		if !lastUnderscore {
			b.WriteByte('_')
			lastUnderscore = true
		}
	}
	return strings.Trim(b.String(), "_")
}

func quoteInFilter(values []string) string {
	quoted := make([]string, 0, len(values))
	for _, v := range values {
		quoted = append(quoted, fmt.Sprintf("%q", v))
	}
	return strings.Join(quoted, ",")
}

func writePostgrestErr(w http.ResponseWriter, err error) {
	var pe *postgrest.Error
	if errors.As(err, &pe) {
		writeJSON(w, http.StatusOK, map[string]string{"error": string(pe.Body)})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"error": err.Error()})
}
