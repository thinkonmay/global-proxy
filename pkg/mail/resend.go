package mail

import (
	"context"
	"fmt"

	"github.com/resend/resend-go/v2"
)

// Sender delivers transactional email (product mail — not admin OTP).
type Sender interface {
	Send(ctx context.Context, p SendParams) (resendID string, err error)
}

type SendParams struct {
	To, Subject, HTML, Text string
}

// ResendSender sends mail via the official Resend Go SDK.
type ResendSender struct {
	client *resend.Client
	from   string
}

func NewResendSender(apiKey, from string) *ResendSender {
	if apiKey == "" || from == "" {
		return nil
	}
	return &ResendSender{
		client: resend.NewClient(apiKey),
		from:   from,
	}
}

func (s *ResendSender) Send(ctx context.Context, p SendParams) (string, error) {
	if s == nil || s.client == nil {
		return "", fmt.Errorf("resend sender not configured")
	}
	params := &resend.SendEmailRequest{
		From:    s.from,
		To:      []string{p.To},
		Subject: p.Subject,
		Html:    p.HTML,
		Text:    p.Text,
	}
	resp, err := s.client.Emails.SendWithContext(ctx, params)
	if err != nil {
		return "", err
	}
	if resp == nil {
		return "", fmt.Errorf("resend: empty response")
	}
	return resp.Id, nil
}
