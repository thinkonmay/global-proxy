package ops

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/httpx"
	"github.com/thinkonmay/global-proxy/api/pkg/admingate"
	"github.com/thinkonmay/global-proxy/api/pkg/metricsagg"
	"github.com/thinkonmay/global-proxy/api/pkg/router"
	"github.com/thinkonmay/global-proxy/api/pkg/vaultpki"
)

const issueTimeout = 15 * time.Second

// Config configures SSO-gated the-red mTLS issuance (D27 / B12).
type Config struct {
	VaultURL      string
	VaultUsername string
	VaultPassword string
	PKIMount      string
	PKIRole       string
	CertTTL       string
	Gate          *admingate.Gate
}

// Handler serves /v1/ops/* for internal tooling authenticated via admin SSO.
type Handler struct {
	cfg Config
}

func New(cfg Config) *Handler {
	cfg.VaultURL = strings.TrimRight(strings.TrimSpace(cfg.VaultURL), "/")
	if cfg.VaultUsername == "" {
		cfg.VaultUsername = "gateway-ops"
	}
	cfg.VaultPassword = strings.TrimSpace(cfg.VaultPassword)
	if cfg.PKIMount == "" {
		cfg.PKIMount = "pki"
	}
	if cfg.PKIRole == "" {
		cfg.PKIRole = "the-red"
	}
	if cfg.CertTTL == "" {
		cfg.CertTTL = "8h"
	}
	return &Handler{cfg: cfg}
}

func (h *Handler) Register(mux *http.ServeMux) {
	if h == nil || h.cfg.Gate == nil {
		return
	}
	v1 := router.V1(mux)
	v1.POST("/ops/mtls/issue", h.IssueMTLS)
}

func (h *Handler) IssueMTLS(w http.ResponseWriter, r *http.Request) {
	sess, ok := h.cfg.Gate.SessionFromBearer(r)
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "admin SSO required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), issueTimeout)
	defer cancel()

	mat, err := vaultpki.Issue(ctx, vaultpki.IssueRequest{
		Addr:       h.cfg.VaultURL,
		Username:   h.cfg.VaultUsername,
		Password:   h.cfg.VaultPassword,
		PKIMount:   h.cfg.PKIMount,
		PKIRole:    h.cfg.PKIRole,
		TTL:        h.cfg.CertTTL,
		CommonName: metricsagg.TheRedCN(sess.Email),
	})
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "failed to issue certificate")
		return
	}

	leaf, err := mat.Leaf()
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "invalid issued certificate")
		return
	}

	httpx.WriteData(w, map[string]any{
		"email":      sess.Email,
		"cert_pem":   string(mat.CertPEM),
		"key_pem":    string(mat.KeyPEM),
		"ca_pem":     string(mat.CACertPEM),
		"expires_at": leaf.NotAfter.UTC().Format(time.RFC3339),
	})
}

// IssueResponse is the payload returned by POST /v1/ops/mtls/issue.
type IssueResponse struct {
	Email     string `json:"email"`
	CertPEM   string `json:"cert_pem"`
	KeyPEM    string `json:"key_pem"`
	CAPEM     string `json:"ca_pem"`
	ExpiresAt string `json:"expires_at"`
}

// ParseIssueResponse decodes the gateway {"data": ...} envelope.
func ParseIssueResponse(body []byte) (IssueResponse, error) {
	var envelope struct {
		Data IssueResponse `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return IssueResponse{}, err
	}
	if envelope.Data.CertPEM == "" || envelope.Data.KeyPEM == "" {
		return IssueResponse{}, json.Unmarshal(body, &envelope.Data)
	}
	return envelope.Data, nil
}
