package gamification

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/auth"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/httpx"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/pkg/router"
	"github.com/thinkonmay/global-proxy/api/pkg/usage"
)

const gamificationQueryTimeout = 5 * time.Second

// Handler serves /v1/gamification/* (F16).
type Handler struct {
	pr        *postgrest.Client
	usage     *usage.Querier
	transport http.RoundTripper
}

func New(pr *postgrest.Client, rt http.RoundTripper, usageQ *usage.Querier) *Handler {
	if rt == nil {
		rt = http.DefaultTransport
	}
	return &Handler{pr: pr, usage: usageQ, transport: rt}
}

func (h *Handler) Register(mux *http.ServeMux) {
	v1 := router.V1(mux)
	v1.GET("/gamification/missions", h.ListMissions)
	v1.POST("/gamification/missions/{code}/claim", h.ClaimMission)
	v1.GET("/gamification/stars", h.StarBalance)
	v1.GET("/gamification/heatmap", h.Heatmap)
	v1.GET("/gamification/stars/leaderboard", h.Leaderboard)
	v1.GET("/gamification/rank-rewards", h.RankRewards)
}

func (h *Handler) ListMissions(w http.ResponseWriter, r *http.Request) {
	email, ok, status, msg := auth.RequireUser(r.Context(), r, h.transport)
	if !ok {
		auth.WriteAuthErr(w, status, msg)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), gamificationQueryTimeout)
	defer cancel()

	data, err := userMissionsV2(ctx, h.pr, h.usage, email)
	if err != nil {
		httpx.WriteUpstreamErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]json.RawMessage{"data": data})
}

func (h *Handler) ClaimMission(w http.ResponseWriter, r *http.Request) {
	code := strings.TrimSpace(r.PathValue("code"))
	if code == "" {
		httpx.WriteError(w, http.StatusBadRequest, "mission code required")
		return
	}
	email, ok, status, msg := auth.RequireUser(r.Context(), r, h.transport)
	if !ok {
		auth.WriteAuthErr(w, status, msg)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), gamificationQueryTimeout)
	defer cancel()

	out, err := claimMission(ctx, h.pr, h.usage, email, code)
	if err != nil {
		httpx.WriteUpstreamErr(w, err)
		return
	}
	httpx.WriteData(w, out)
}

func (h *Handler) StarBalance(w http.ResponseWriter, r *http.Request) {
	email, ok, status, msg := auth.RequireUser(r.Context(), r, h.transport)
	if !ok {
		auth.WriteAuthErr(w, status, msg)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), gamificationQueryTimeout)
	defer cancel()

	var balance json.RawMessage
	if err := h.pr.RPC(ctx, "get_star_balance", map[string]any{"p_email": email}, &balance); err != nil {
		httpx.WriteUpstreamErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]json.RawMessage{"data": balance})
}

func (h *Handler) Heatmap(w http.ResponseWriter, r *http.Request) {
	email, ok, status, msg := auth.RequireUser(r.Context(), r, h.transport)
	if !ok {
		auth.WriteAuthErr(w, status, msg)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), gamificationQueryTimeout)
	defer cancel()

	data, err := userHeatmap(ctx, h.usage, email)
	if err != nil {
		httpx.WriteUpstreamErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]json.RawMessage{"data": data})
}

func (h *Handler) Leaderboard(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if v := strings.TrimSpace(r.URL.Query().Get("limit")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 {
			limit = n
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), gamificationQueryTimeout)
	defer cancel()

	var rows json.RawMessage
	if err := h.pr.RPC(ctx, "get_star_leaderboard", map[string]any{"limit_count": limit}, &rows); err != nil {
		httpx.WriteUpstreamErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]json.RawMessage{"data": rows})
}

func (h *Handler) RankRewards(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), gamificationQueryTimeout)
	defer cancel()

	var rows json.RawMessage
	if err := h.pr.RPC(ctx, "get_all_rank_rewards", map[string]any{}, &rows); err != nil {
		httpx.WriteUpstreamErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]json.RawMessage{"data": rows})
}
