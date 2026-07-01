package streammtls

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/auth"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/httpx"
	"github.com/thinkonmay/global-proxy/api/pkg/audit"
	"github.com/thinkonmay/global-proxy/api/pkg/router"
	streammtlscn "github.com/thinkonmay/global-proxy/api/pkg/streammtls"
	"github.com/thinkonmay/global-proxy/api/pkg/vaultpki"
)

const issueTimeout = 15 * time.Second

// Config configures GoTrue-gated desktop QUIC mTLS issuance (C2 / D26).
type Config struct {
	VaultURL      string
	VaultUsername string
	VaultPassword string
	PKIMount      string
	PKIRole       string
	CertTTL       string
	Recorder      *audit.Recorder
	Transport     http.RoundTripper
}

// Handler serves POST /v1/stream/mtls/issue for desktop streaming clients.
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
		cfg.PKIRole = "desktop-client"
	}
	if cfg.CertTTL == "" {
		cfg.CertTTL = "2h"
	}
	return &Handler{cfg: cfg}
}

func (h *Handler) Register(mux *http.ServeMux) {
	if h == nil || h.cfg.VaultURL == "" || h.cfg.VaultPassword == "" {
		return
	}
	router.V1(mux).POST("/stream/mtls/issue", h.Issue)
}

type issueRequest struct {
	SessionID string `json:"session_id"`
	VMID      string `json:"vm_id"`
}

// IssueResponse is returned by POST /v1/stream/mtls/issue.
type IssueResponse struct {
	SessionID  string `json:"session_id"`
	VMID       string `json:"vm_id"`
	CommonName string `json:"common_name"`
	CertPEM    string `json:"cert_pem"`
	KeyPEM     string `json:"key_pem"`
	CAPEM      string `json:"ca_pem"`
	ExpiresAt  string `json:"expires_at"`
}

func (h *Handler) Issue(w http.ResponseWriter, r *http.Request) {
	email, ok, status, msg := auth.RequireUser(r.Context(), r, h.cfg.Transport)
	if !ok {
		auth.WriteAuthErr(w, status, msg)
		return
	}

	var req issueRequest
	if err := httpx.ReadJSONBody(r, &req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid body")
		return
	}
	req.SessionID = strings.TrimSpace(req.SessionID)
	req.VMID = strings.TrimSpace(req.VMID)
	if err := streammtlscn.ValidateIDs(req.SessionID, req.VMID); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	cn := streammtlscn.DesktopCN(req.SessionID, req.VMID)

	ctx, cancel := context.WithTimeout(r.Context(), issueTimeout)
	defer cancel()

	mat, err := vaultpki.Issue(ctx, vaultpki.IssueRequest{
		Addr:       h.cfg.VaultURL,
		Username:   h.cfg.VaultUsername,
		Password:   h.cfg.VaultPassword,
		PKIMount:   h.cfg.PKIMount,
		PKIRole:    h.cfg.PKIRole,
		TTL:        h.cfg.CertTTL,
		CommonName: cn,
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

	h.auditIssue(r, email, req.SessionID, req.VMID, cn)

	httpx.WriteData(w, IssueResponse{
		SessionID:  req.SessionID,
		VMID:       req.VMID,
		CommonName: cn,
		CertPEM:    string(mat.CertPEM),
		KeyPEM:     string(mat.KeyPEM),
		CAPEM:      string(mat.CACertPEM),
		ExpiresAt:  leaf.NotAfter.UTC().Format(time.RFC3339),
	})
}

func (h *Handler) auditIssue(r *http.Request, email, sessionID, vmID, cn string) {
	if h.cfg.Recorder == nil {
		return
	}
	ev := audit.Event{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		RequestID: audit.RequestID(r.Context()),
		UserEmail: email,
		Route:     r.URL.Path,
		Method:    r.Method,
		Action:    "stream.mtls.issue",
		Component: "gateway",
		Detail:    "session_id=" + sessionID + " vm_id=" + vmID + " cn=" + cn,
	}
	h.cfg.Recorder.Record(ev)
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
