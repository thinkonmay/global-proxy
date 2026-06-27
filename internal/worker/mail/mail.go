// Package mail consumes product/in-app mail jobs off the bus, writes the
// Postgres ledger, and sends transactional email via Resend when requested.
package mail

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/thinkonmay/global-proxy/api/config"
	pkgmail "github.com/thinkonmay/global-proxy/api/pkg/mail"
	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	"github.com/thinkonmay/global-proxy/api/pkg/idempotency"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

type Handler struct {
	idem   *idempotency.Guard
	pr     *postgrest.Client
	sender pkgmail.Sender
}

func New(idem *idempotency.Guard, pr *postgrest.Client, cfg config.Mail) *Handler {
	return &Handler{
		idem:   idem,
		pr:     pr,
		sender: pkgmail.NewResendSender(cfg.APIKey, cfg.From),
	}
}

func (h *Handler) Init(eventBus bus.Client) {
	bus.Subscribe(
		eventBus,
		model.TopicMailJob,
		"worker-mail",
		h.handle,
		bus.WithConcurrency(8),
		bus.WithMaxDeliver(5),
	)
}

func (h *Handler) handle(ctx context.Context, p model.MailJobMsg) error {
	return h.idem.Run(ctx, "mail-"+p.RequestID, func(ctx context.Context) error {
		row, err := h.ensureMail(ctx, p)
		if err != nil {
			return err
		}
		p.MailID = row.ID
		if terminalStatus(row.Status) {
			return nil
		}
		return h.dispatch(ctx, p, row.Status)
	})
}

type mailRow struct {
	ID     int64  `json:"id"`
	Status string `json:"status"`
}

func terminalStatus(status string) bool {
	switch status {
	case "sent", "failed", "skipped":
		return true
	default:
		return false
	}
}

func (h *Handler) ensureMail(ctx context.Context, p model.MailJobMsg) (mailRow, error) {
	sendEmail := p.SendEmail
	inApp := p.InApp
	if !sendEmail && !inApp {
		inApp = true
	}
	body := map[string]any{
		"request_id": p.RequestID,
		"email":      strings.ToLower(strings.TrimSpace(p.Email)),
		"title":      p.Title,
		"subject":    p.Subject,
		"finalHTML":  p.FinalHTML,
		"text_body":  p.TextBody,
		"send_email": sendEmail,
		"in_app":     inApp,
		"status":     "pending",
	}
	if len(p.CTA) > 0 {
		body["cta"] = json.RawMessage(p.CTA)
	}
	if len(p.Metadata) > 0 {
		body["metadata"] = json.RawMessage(p.Metadata)
	}
	var created []mailRow
	err := h.pr.Insert(ctx, "mail", body, &created)
	if err == nil {
		if len(created) == 0 {
			return mailRow{}, fmt.Errorf("insert mail returned no id (request %s)", p.RequestID)
		}
		return created[0], nil
	}
	if postgrest.IsConflict(err) {
		return h.mailByRequest(ctx, p.RequestID)
	}
	return mailRow{}, err
}

func (h *Handler) mailByRequest(ctx context.Context, requestID string) (mailRow, error) {
	q := url.Values{}
	q.Set("select", "id,status")
	q.Set("request_id", "eq."+requestID)
	q.Set("limit", "1")
	var rows []mailRow
	if err := h.pr.SelectService(ctx, "mail", q, &rows); err != nil {
		return mailRow{}, err
	}
	if len(rows) == 0 {
		return mailRow{}, fmt.Errorf("mail for request %s not found", requestID)
	}
	return rows[0], nil
}

func (h *Handler) dispatch(ctx context.Context, p model.MailJobMsg, currentStatus string) error {
	if currentStatus != "pending" {
		return nil
	}
	if !p.SendEmail {
		return h.patchMail(ctx, p.MailID, "skipped", "", nil)
	}
	if h.sender == nil {
		return h.patchMail(ctx, p.MailID, "failed", "", []string{"resend not configured"})
	}
	text := p.TextBody
	if text == "" {
		text = plainFromHTML(p.FinalHTML)
	}
	subject := p.Subject
	if subject == "" {
		subject = p.Title
	}
	resendID, err := h.sender.Send(ctx, pkgmail.SendParams{
		To:      strings.ToLower(strings.TrimSpace(p.Email)),
		Subject: subject,
		HTML:    p.FinalHTML,
		Text:    text,
	})
	if err != nil {
		slog.Error("mail send failed", "request_id", p.RequestID, "mail_id", p.MailID, "err", err)
		return h.patchMail(ctx, p.MailID, "failed", "", []string{err.Error()})
	}
	return h.patchMail(ctx, p.MailID, "sent", resendID, nil)
}

func (h *Handler) patchMail(ctx context.Context, mailID int64, status, resendID string, errs []string) error {
	patch := map[string]any{
		"status": status,
	}
	if resendID != "" {
		patch["resend_id"] = resendID
	}
	if status == "sent" || status == "skipped" {
		patch["sent_at"] = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if len(errs) > 0 {
		patch["errors"] = errs
	}
	q := url.Values{}
	q.Set("id", fmt.Sprintf("eq.%d", mailID))
	if err := h.pr.Update(ctx, "mail", q, patch, nil); err != nil {
		slog.Error("patch mail failed", "mail_id", mailID, "err", err)
		return err
	}
	return nil
}

func plainFromHTML(html string) string {
	s := strings.ReplaceAll(html, "<br>", "\n")
	s = strings.ReplaceAll(s, "<br/>", "\n")
	s = strings.ReplaceAll(s, "<br />", "\n")
	var b strings.Builder
	inTag := false
	for _, r := range s {
		switch {
		case r == '<':
			inTag = true
		case r == '>':
			inTag = false
		case !inTag:
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}
