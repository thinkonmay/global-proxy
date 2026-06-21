package payment

import (
	"context"
	"encoding/json"
	"net/url"
)

type payOSConfig struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	ChecksumKey  string `json:"checksum_key"`
}

type stripeConfig struct {
	SecretKey string `json:"secret_key"`
}

type payerMaxConfig struct {
	AppID      string `json:"app_id"`
	MerchantNo string `json:"merchant_no"`
	BaseURL    string `json:"base_url"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

type payssionConfig struct {
	APIKey    string `json:"api_key"`
	PMID      string `json:"pm_id"`
	SecretKey string `json:"secret_key"`
	Link      string `json:"link"`
}

type providerConfig struct {
	PayOS     payOSConfig
	Stripe    stripeConfig
	PayerMax  payerMaxConfig
	Payssion  payssionConfig
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

func (s *Service) loadProviderConfig(ctx context.Context) (providerConfig, error) {
	var rows []struct {
		Name  string          `json:"name"`
		Value json.RawMessage `json:"value"`
	}
	q := url.Values{}
	q.Set("select", "name,value")
	q.Set("name", "in.(payos,stripe,payermax,payssion)")
	if err := s.pr.SelectService(ctx, "constant", q, &rows); err != nil {
		return providerConfig{}, err
	}
	var out providerConfig
	for _, row := range rows {
		switch row.Name {
		case "payos":
			_ = json.Unmarshal(row.Value, &out.PayOS)
		case "stripe":
			_ = json.Unmarshal(row.Value, &out.Stripe)
		case "payermax":
			_ = json.Unmarshal(row.Value, &out.PayerMax)
		case "payssion":
			_ = json.Unmarshal(row.Value, &out.Payssion)
		}
	}
	return out, nil
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
