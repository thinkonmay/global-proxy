package payment

import (
	"context"
	"encoding/json"
	"net/url"
)

type payOSConfig struct {
	ClientID     string `json:"client_id" mapstructure:"clientId"`
	ClientSecret string `json:"client_secret" mapstructure:"clientSecret"`
	ChecksumKey  string `json:"checksum_key" mapstructure:"checksumKey"`
}

type stripeConfig struct {
	SecretKey string `json:"secret_key" mapstructure:"secretKey"`
}

type payerMaxConfig struct {
	AppID      string `json:"app_id" mapstructure:"appId"`
	MerchantNo string `json:"merchant_no" mapstructure:"merchantNo"`
	BaseURL    string `json:"base_url" mapstructure:"baseURL"`
	PrivateKey string `json:"private_key" mapstructure:"privateKey"`
	PublicKey  string `json:"public_key" mapstructure:"publicKey"`
}

type payssionConfig struct {
	APIKey    string `json:"api_key" mapstructure:"apiKey"`
	PMID      string `json:"pm_id" mapstructure:"pmId"`
	SecretKey string `json:"secret_key" mapstructure:"secretKey"`
	Link      string `json:"link" mapstructure:"link"`
}

type providerConfig struct {
	PayOS    payOSConfig
	Stripe   stripeConfig
	PayerMax payerMaxConfig
	Payssion payssionConfig
}

type txnRow struct {
	ID       int64           `json:"id"`
	Email    string          `json:"email"`
	Amount   int64           `json:"amount"`
	Currency string          `json:"currency"`
	Provider string          `json:"provider"`
	Status   string          `json:"status"`
	Data     json.RawMessage `json:"data"`
	Metadata json.RawMessage `json:"metadata"`
	ExpireAt string          `json:"expire_at"`
}

func (s *Service) loadProviderConfig() providerConfig {
	return s.providers
}

func (s *Service) loadExchangeRate(ctx context.Context, currency string) (float64, error) {
	var rows []struct {
		Rate float64 `json:"rate_to_system_credit"`
	}
	q := url.Values{}
	q.Set("select", "rate_to_system_credit")
	q.Set("currency", "eq."+currency)
	q.Set("limit", "1")
	if err := s.pr.SelectService(ctx, "currency_rates", q, &rows); err != nil {
		return 0, err
	}
	if len(rows) == 0 || rows[0].Rate == 0 {
		return 0, errUnsupportedCurrency(currency)
	}
	return rows[0].Rate, nil
}

func (s *Service) loadTransaction(ctx context.Context, id int64) (txnRow, error) {
	var rows []txnRow
	q := url.Values{}
	q.Set("select", "id,email,amount,currency,provider,status,data,metadata,expire_at")
	q.Set("id", "eq."+formatID(id))
	q.Set("limit", "1")
	if err := s.pr.SelectService(ctx, "transactions", q, &rows); err != nil {
		return txnRow{}, err
	}
	if len(rows) == 0 {
		return txnRow{}, errNotFound(id)
	}
	return rows[0], nil
}

func dataIsEmpty(raw json.RawMessage) bool {
	if len(raw) == 0 || string(raw) == "null" {
		return true
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return false
	}
	return len(m) == 0
}
