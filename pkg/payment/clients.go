package payment

import (
	"encoding/json"
	"time"

	payos "github.com/payOSHQ/payos-lib-golang/v2"
	"github.com/stripe/stripe-go/v82"
)

func (s *Service) stripeClient(secretKey string) *stripe.Client {
	backends := stripe.NewBackendsWithConfig(&stripe.BackendConfig{
		HTTPClient: s.http,
	})
	return stripe.NewClient(secretKey, stripe.WithBackends(backends))
}

func (s *Service) payosClient(cfg payOSConfig) (*payos.PayOS, error) {
	return payos.NewPayOS(&payos.PayOSOptions{
		ClientId:    cfg.ClientID,
		ApiKey:      cfg.ClientSecret,
		ChecksumKey: cfg.ChecksumKey,
		HTTPClient:  s.http,
		Timeout:     15 * time.Second,
	})
}

func wrapPayOSResponse(data any) (json.RawMessage, error) {
	return json.Marshal(map[string]any{
		"code": "00",
		"desc": "success",
		"data": data,
	})
}
