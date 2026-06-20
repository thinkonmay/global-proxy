package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/thinkonmay/global-proxy/api/config"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/pkg/rpc"
)

const pbAuthTimeout = 3 * time.Second

type GlobalRPCHandler struct {
	pr         *postgrest.Client
	rpcPass1   string
	httpClient *http.Client
}

func NewGlobalRPCHandler(cfg config.Config, pr *postgrest.Client) *GlobalRPCHandler {
	return &GlobalRPCHandler{
		pr:       pr,
		rpcPass1: cfg.RPC.Password1,
		httpClient: &http.Client{
			Timeout: pbAuthTimeout,
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
		recordEmail, err := h.pocketBaseAuthRefresh(r.Context(), req.Issuer, authHeader)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
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

func (h *GlobalRPCHandler) pocketBaseAuthRefresh(ctx context.Context, issuer, token string) (string, error) {
	base := strings.TrimRight(issuer, "/")
	url := base + "/api/collections/users/auth-refresh"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, http.NoBody)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", token)
	resp, err := h.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", errors.New("pocketbase auth refresh failed")
	}
	var out struct {
		Record struct {
			Email string `json:"email"`
		} `json:"record"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", err
	}
	if out.Record.Email == "" {
		return "", errors.New("empty pocketbase user email")
	}
	return out.Record.Email, nil
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
