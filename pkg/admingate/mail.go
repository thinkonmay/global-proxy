package admingate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Mailer delivers OTP codes to admins.
type Mailer interface {
	SendOTP(ctx context.Context, to, code string) error
}

// ResendMailer sends mail via Resend HTTP API.
type ResendMailer struct {
	APIKey string
	From   string
	Client *http.Client
}

func (m *ResendMailer) SendOTP(ctx context.Context, to, code string) error {
	if m.APIKey == "" {
		return fmt.Errorf("resend api key not configured")
	}
	client := m.Client
	if client == nil {
		client = http.DefaultClient
	}
	body, _ := json.Marshal(map[string]any{
		"from":    m.From,
		"to":      []string{to},
		"subject": "Thinkmay admin login code",
		"text":    fmt.Sprintf("Your one-time admin code is %s. It expires in 10 minutes.", code),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.resend.com/emails", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+m.APIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("resend status %d", resp.StatusCode)
	}
	return nil
}

// LogMailer prints OTP codes (dev/tests only).
type LogMailer struct{}

func (LogMailer) SendOTP(_ context.Context, to, code string) error {
	fmt.Printf("admingate: OTP for %s = %s\n", to, code)
	return nil
}

func defaultHTTPClient() *http.Client {
	return &http.Client{Timeout: 15 * time.Second}
}

// DefaultHTTPClient is the Resend HTTP client default.
func DefaultHTTPClient() *http.Client {
	return defaultHTTPClient()
}
