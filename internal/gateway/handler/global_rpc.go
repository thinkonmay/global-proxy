package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/pkg/pocketbase"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/pkg/rpc"
	"github.com/thinkonmay/global-proxy/api/pkg/usage"
)

const pbAuthTimeout = 3 * time.Second

type GlobalRPCHandler struct {
	pr         *postgrest.Client
	rpcPass1   string
	httpClient *http.Client
	usage      *usage.Querier
}

func NewGlobalRPCHandler(cfg config.Config, pr *postgrest.Client, rt http.RoundTripper, usageQ *usage.Querier) *GlobalRPCHandler {
	if rt == nil {
		rt = http.DefaultTransport
	}
	return &GlobalRPCHandler{
		pr:       pr,
		rpcPass1: cfg.RPC.Password1,
		usage:    usageQ,
		httpClient: &http.Client{
			Timeout:   pbAuthTimeout,
			Transport: rt,
		},
	}
}

func (h *GlobalRPCHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/global_rpc", h.Serve)
	mux.HandleFunc("POST /api/global_rpc/", h.Serve)
}

func (h *GlobalRPCHandler) Serve(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	req, err := rpc.DecodeRPC(body, h.rpcPass1)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if email, needsAuth := rpc.RequestEmail(req.Args); needsAuth {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Unauthorized: No auth header"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), pbAuthTimeout)
		defer cancel()
		recordEmail, err := pocketbase.UserEmailFromRefresh(ctx, req.Issuer, authHeader, h.httpClient.Transport)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "pocketbase auth refresh failed"})
			return
		}
		if recordEmail != email {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Unauthorized: Email mismatch"})
			return
		}
	}

	var args any
	if len(req.Args) > 0 {
		_ = json.Unmarshal(req.Args, &args)
	}

	var result json.RawMessage
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	if h.usage != nil {
		if data, ok, err := h.serveUsageRPC(ctx, req.RPC, args); err != nil {
			h.sendEncrypted(w, req.ResponseKey, rpc.ResponseEnvelope{Error: mustJSON(err.Error())})
			return
		} else if ok {
			h.sendEncrypted(w, req.ResponseKey, rpc.ResponseEnvelope{Data: data})
			return
		}
	}

	if err := h.pr.RPC(ctx, req.RPC, args, &result); err != nil {
		var pe *postgrest.Error
		if errors.As(err, &pe) {
			h.sendEncrypted(w, req.ResponseKey, rpc.ResponseEnvelope{Error: json.RawMessage(pe.Body)})
			return
		}
		h.sendEncrypted(w, req.ResponseKey, rpc.ResponseEnvelope{Error: mustJSON(err.Error())})
		return
	}
	h.sendEncrypted(w, req.ResponseKey, rpc.ResponseEnvelope{Data: result})
}

func (h *GlobalRPCHandler) serveUsageRPC(ctx context.Context, rpcName string, args any) (json.RawMessage, bool, error) {
	switch rpcName {
	case "get_user_heatmap":
		if h.usage == nil {
			return nil, false, nil
		}
		email := usage.UsageRPCEmail(mustRawArgs(args))
		if email == "" {
			return nil, true, errors.New("target_email required")
		}
		rows, err := h.usage.Heatmap(ctx, email, 365)
		if err != nil {
			return nil, true, err
		}
		data, err := usage.HeatmapJSON(rows)
		return data, true, err

	case "get_data_usage":
		if h.usage == nil {
			return nil, false, nil
		}
		email := usage.UsageRPCEmail(mustRawArgs(args))
		if email == "" {
			return nil, true, errors.New("email required")
		}
		rows, err := h.usage.DataUsageHistory(ctx, email, 168)
		if err != nil {
			return nil, true, err
		}
		data, err := usage.DataUsageJSON(rows)
		return data, true, err

	case "get_user_missions_v2":
		if h.usage == nil {
			return nil, false, nil
		}
		email := usage.UsageRPCEmail(mustRawArgs(args))
		if email == "" {
			return nil, true, errors.New("p_email required")
		}
		var raw json.RawMessage
		if err := h.pr.RPC(ctx, rpcName, args, &raw); err != nil {
			return nil, true, err
		}
		merged, err := usage.MergeMissionUsageProgress(ctx, h.usage, email, raw)
		return merged, true, err

	case "claim_mission_v2":
		if h.usage == nil {
			return nil, false, nil
		}
		return h.claimMissionWithUsage(ctx, args)

	default:
		return nil, false, nil
	}
}

func (h *GlobalRPCHandler) claimMissionWithUsage(ctx context.Context, args any) (json.RawMessage, bool, error) {
	var a struct {
		PEmail      string `json:"p_email"`
		PMissionCode string `json:"p_mission_code"`
	}
	raw := mustRawArgs(args)
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &a)
	}
	if a.PEmail == "" || a.PMissionCode == "" {
		return nil, true, errors.New("p_email and p_mission_code required")
	}

	type missionTypeRow struct {
		Type string `json:"type"`
	}
	var missions []missionTypeRow
	q := url.Values{}
	q.Set("select", "type")
	q.Set("code", "eq."+a.PMissionCode)
	q.Set("limit", "1")
	if err := h.pr.Select(ctx, "missions", q, &missions); err != nil {
		return nil, true, err
	}
	if len(missions) == 0 {
		var out bool
		if err := h.pr.RPC(ctx, "claim_mission_v2", args, &out); err != nil {
			return nil, true, err
		}
		return mustJSONBool(out)
	}

	switch missions[0].Type {
	case "DAILY_SESSION", "PLAY_STREAK":
		var progress int
		var err error
		if missions[0].Type == "DAILY_SESSION" {
			progress, err = h.usage.DailySessionCount(ctx, a.PEmail)
		} else {
			progress, err = h.usage.PlayStreak(ctx, a.PEmail)
		}
		if err != nil {
			return nil, true, err
		}
		var out bool
		if err := h.pr.RPC(ctx, "claim_mission_gateway_v2", map[string]any{
			"p_email":        a.PEmail,
			"p_mission_code": a.PMissionCode,
			"p_progress":     progress,
		}, &out); err != nil {
			return nil, true, err
		}
		return mustJSONBool(out)
	default:
		var out bool
		if err := h.pr.RPC(ctx, "claim_mission_v2", args, &out); err != nil {
			return nil, true, err
		}
		return mustJSONBool(out)
	}
}

func mustRawArgs(args any) json.RawMessage {
	switch v := args.(type) {
	case json.RawMessage:
		return v
	case []byte:
		return json.RawMessage(v)
	default:
		b, _ := json.Marshal(args)
		return b
	}
}

func mustJSONBool(v bool) (json.RawMessage, bool, error) {
	b, err := json.Marshal(v)
	return b, true, err
}

func (h *GlobalRPCHandler) sendEncrypted(w http.ResponseWriter, responseKey string, env rpc.ResponseEnvelope) {
	if env.Error == nil && env.Data == nil {
		env.Data = json.RawMessage("null")
	}
	out, err := rpc.EncodeRPCResponse(env, responseKey)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}

func mustJSON(s string) json.RawMessage {
	b, _ := json.Marshal(map[string]string{"message": s})
	return b
}
