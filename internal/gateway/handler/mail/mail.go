// Package mail serves /v1/mail: enqueue product mail jobs and list in-app mail.
package mail

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/auth"
	"github.com/thinkonmay/global-proxy/api/internal/gateway/handler/httpx"
	pkgmail "github.com/thinkonmay/global-proxy/api/pkg/mail"
	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/pkg/router"
	"github.com/thinkonmay/global-proxy/api/pkg/validator"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

const (
	mailQueryTimeout   = 5 * time.Second
	mailPublishTimeout = 10 * time.Second
)

type Handler struct {
	pr         *postgrest.Client
	bus        bus.Client
	serviceKey string
	transport  http.RoundTripper
}

func New(pr *postgrest.Client, b bus.Client, serviceKey string, rt http.RoundTripper) *Handler {
	if rt == nil {
		rt = http.DefaultTransport
	}
	return &Handler{pr: pr, bus: b, serviceKey: strings.TrimSpace(serviceKey), transport: rt}
}

func (h *Handler) Register(mux *http.ServeMux) {
	if h.bus == nil {
		return
	}
	v1 := router.V1(mux)
	v1.GET("/mail", h.List)
	v1.POST("/mail", h.Enqueue)
}

type enqueueRequest struct {
	Email     string          `json:"email" validate:"required,email"`
	Title     string          `json:"title"`
	Subject   string          `json:"subject"`
	FinalHTML string          `json:"final_html"`
	TextBody  string          `json:"text_body"`
	SendEmail *bool           `json:"send_email"`
	InApp     *bool           `json:"in_app"`
	CTA       json.RawMessage `json:"cta"`
	Metadata  json.RawMessage `json:"metadata"`
}

// Enqueue validates the payload and publishes a mail job. Trusted callers use
// the PostgREST service role key; end users cannot enqueue mail for others.
func (h *Handler) Enqueue(w http.ResponseWriter, r *http.Request) {
	if !h.requireServiceKey(w, r) {
		return
	}
	var req enqueueRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if err := validator.Validate(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	sendEmail := true
	if req.SendEmail != nil {
		sendEmail = *req.SendEmail
	}
	inApp := true
	if req.InApp != nil {
		inApp = *req.InApp
	}

	requestID := uuid.NewString()
	msg := model.MailJobMsg{
		RequestID: requestID,
		Email:     strings.ToLower(strings.TrimSpace(req.Email)),
		Title:     req.Title,
		Subject:   req.Subject,
		FinalHTML: req.FinalHTML,
		TextBody:  req.TextBody,
		SendEmail: sendEmail,
		InApp:     inApp,
		CTA:       req.CTA,
		Metadata:  req.Metadata,
	}

	ctx, cancel := context.WithTimeout(r.Context(), mailPublishTimeout)
	defer cancel()
	if err := pkgmail.Publish(ctx, h.bus, msg); err != nil {
		httpx.WriteJSON(w, http.StatusServiceUnavailable, map[string]bool{"global_unavailable": true})
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, map[string]string{"id": requestID})
}

type mailItem struct {
	Title     string `json:"title"`
	Content   string `json:"content"`
	Created   string `json:"created"`
	FinalHTML string `json:"finalHTML"`
}

// List returns in-app mail for the authenticated user (last 24 hours).
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	email, ok, status, msg := auth.RequireUser(r.Context(), r, h.transport)
	if !ok {
		auth.WriteAuthErr(w, status, msg)
		return
	}
	since := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)
	q := url.Values{}
	q.Set("select", "title,subject,created,finalHTML")
	q.Set("email", "eq."+email)
	q.Set("in_app", "eq.true")
	q.Set("created", "gte."+since)
	q.Set("order", "created.desc")

	ctx, cancel := context.WithTimeout(r.Context(), mailQueryTimeout)
	defer cancel()

	var rows []struct {
		Title     string `json:"title"`
		Subject   string `json:"subject"`
		Created   string `json:"created"`
		FinalHTML string `json:"finalHTML"`
	}
	if err := h.pr.SelectService(ctx, "mail", q, &rows); err != nil {
		httpx.WriteUpstreamErr(w, err)
		return
	}
	out := make([]mailItem, 0, len(rows))
	for _, row := range rows {
		html := row.FinalHTML
		out = append(out, mailItem{
			Title:     row.Title,
			Content:   html,
			Created:   row.Created,
			FinalHTML: html,
		})
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (h *Handler) requireServiceKey(w http.ResponseWriter, r *http.Request) bool {
	if h.serviceKey == "" {
		httpx.WriteError(w, http.StatusServiceUnavailable, "mail enqueue disabled")
		return false
	}
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	const prefix = "Bearer "
	if !strings.HasPrefix(authHeader, prefix) || strings.TrimSpace(strings.TrimPrefix(authHeader, prefix)) != h.serviceKey {
		httpx.WriteError(w, http.StatusUnauthorized, "authorization required")
		return false
	}
	return true
}
