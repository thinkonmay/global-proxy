package payment

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	payos "github.com/payOSHQ/payos-lib-golang/v2"
	payermaxsdk "github.com/shareit-payermax/payermax-server-sdk-go/payermax"
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

func (s *Service) payermaxClient(cfg payerMaxConfig) (*payermaxsdk.Client, error) {
	if cfg.PrivateKey == "" {
		return nil, fmt.Errorf("payermax private_key not configured")
	}
	if cfg.PublicKey == "" {
		return nil, fmt.Errorf("payermax public_key not configured for SDK")
	}
	base := strings.TrimRight(cfg.BaseURL, "/")
	return payermaxsdk.CreateClient(
		cfg.AppID,
		cfg.MerchantNo,
		cfg.PrivateKey,
		cfg.PublicKey,
		"", "",
		payermaxsdk.ClientSettings{
			BaseUrl:       base,
			ClientTimeout: 15 * time.Second,
		},
	)
}

func wrapPayOSResponse(data any) (json.RawMessage, error) {
	return json.Marshal(map[string]any{
		"code": "00",
		"desc": "success",
		"data": data,
	})
}
