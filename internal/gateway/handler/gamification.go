package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/pkg/usage"
)

const gamificationQueryTimeout = 5 * time.Second

// GamificationHandler serves /v1/gamification/* (F16).
type GamificationHandler struct {
	pr        *postgrest.Client
	usage     *usage.Querier
	transport http.RoundTripper
}

func NewGamificationHandler(pr *postgrest.Client, rt http.RoundTripper, usageQ *usage.Querier) *GamificationHandler {
	if rt == nil {
		rt = http.DefaultTransport
	}
	return &GamificationHandler{pr: pr, usage: usageQ, transport: rt}
}

func (h *GamificationHandler) Register(mux *http.ServeMux) {
	routes := []struct {
		method string
		path   string
		fn     http.HandlerFunc
	}{
		{http.MethodGet, "/v1/gamification/missions", h.ListMissions},
		{http.MethodPost, "/v1/gamification/missions/{code}/claim", h.ClaimMission},
		{http.MethodGet, "/v1/gamification/stars", h.StarBalance},
		{http.MethodGet, "/v1/gamification/heatmap", h.Heatmap},
		{http.MethodGet, "/v1/gamification/stars/leaderboard", h.Leaderboard},
		{http.MethodGet, "/v1/gamification/rank-rewards", h.RankRewards},
	}
	for _, route := range routes {
		mux.HandleFunc(route.method+" "+route.path, route.fn)
		mux.HandleFunc(route.method+" "+route.path+"/", route.fn)
	}
}

func (h *GamificationHandler) ListMissions(w http.ResponseWriter, r *http.Request) {
	email, ok, status, msg := requireUser(r.Context(), r, h.transport)
	if !ok {
		writeAuthErr(w, status, msg)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), gamificationQueryTimeout)
	defer cancel()

	data, err := userMissionsV2(ctx, h.pr, h.usage, email)
	if err != nil {
		writeGamificationErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]json.RawMessage{"data": data})
}

func (h *GamificationHandler) ClaimMission(w http.ResponseWriter, r *http.Request) {
	code := strings.TrimSpace(r.PathValue("code"))
	if code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "mission code required"})
		return
	}
	email, ok, status, msg := requireUser(r.Context(), r, h.transport)
	if !ok {
		writeAuthErr(w, status, msg)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), gamificationQueryTimeout)
	defer cancel()

	out, err := claimMission(ctx, h.pr, h.usage, email, code)
	if err != nil {
		writeGamificationErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": out})
}

func (h *GamificationHandler) StarBalance(w http.ResponseWriter, r *http.Request) {
	email, ok, status, msg := requireUser(r.Context(), r, h.transport)
	if !ok {
		writeAuthErr(w, status, msg)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), gamificationQueryTimeout)
	defer cancel()

	var balance json.RawMessage
	if err := h.pr.RPC(ctx, "get_star_balance", map[string]any{"p_email": email}, &balance); err != nil {
		writeGamificationErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]json.RawMessage{"data": balance})
}

func (h *GamificationHandler) Heatmap(w http.ResponseWriter, r *http.Request) {
	email, ok, status, msg := requireUser(r.Context(), r, h.transport)
	if !ok {
		writeAuthErr(w, status, msg)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), gamificationQueryTimeout)
	defer cancel()

	data, err := userHeatmap(ctx, h.usage, email)
	if err != nil {
		writeGamificationErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]json.RawMessage{"data": data})
}

func (h *GamificationHandler) Leaderboard(w http.ResponseWriter, r *http.Request) {
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
		writeGamificationErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]json.RawMessage{"data": rows})
}

func (h *GamificationHandler) RankRewards(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), gamificationQueryTimeout)
	defer cancel()

	var rows json.RawMessage
	if err := h.pr.RPC(ctx, "get_all_rank_rewards", map[string]any{}, &rows); err != nil {
		writeGamificationErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]json.RawMessage{"data": rows})
}

func writeGamificationErr(w http.ResponseWriter, err error) {
	var pe *postgrest.Error
	if errors.As(err, &pe) {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": strings.TrimSpace(string(pe.Body))})
		return
	}
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
}
