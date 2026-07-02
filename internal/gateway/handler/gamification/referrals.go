package gamification

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/auth"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/httpx"
)

func (h *Handler) ListReferrals(w http.ResponseWriter, r *http.Request) {
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
	email, ok, status, msg := auth.RequireUser(r.Context(), r, h.transport)
	if !ok {
		auth.WriteAuthErr(w, status, msg)
		return
	}
	if !strings.EqualFold(strings.TrimSpace(email), strings.TrimSpace(req.Email)) {
		httpx.WriteError(w, http.StatusForbidden, "email mismatch")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), gamificationQueryTimeout)
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

	// A paid referral = a referred user who owns a machine (active or expired),
	// i.e. has bought a plan. Mirrors get_user_missions_v2's referral-payment count.
	paid := make(map[string]struct{})
	payQ := url.Values{}
	payQ.Set("select", "user_email")
	payQ.Set("user_email", "in.("+quoteInFilter(referred)+")")
	payQ.Set("status", "in.(active,expired)")
	var payments []struct {
		UserEmail string `json:"user_email"`
	}
	_ = h.pr.Select(ctx, "machines", payQ, &payments)
	for _, p := range payments {
		if p.UserEmail != "" {
			paid[p.UserEmail] = struct{}{}
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

func quoteInFilter(values []string) string {
	quoted := make([]string, 0, len(values))
	for _, v := range values {
		quoted = append(quoted, fmt.Sprintf("%q", v))
	}
	return strings.Join(quoted, ",")
}
