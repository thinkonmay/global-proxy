package payment

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

const defaultPollInterval = 10 * time.Second

// Poller replaces pg_cron verify_all_transactions_v2: polls provider APIs and
// PATCHes transaction status in Postgres via PostgREST.
type Poller struct {
	pr         *postgrest.Client
	http       *http.Client
	rsaSigner  string
	log        *slog.Logger
	interval   time.Duration
}

type Config struct {
	RSASignerURL string
	PollEvery    time.Duration
}

func NewPoller(pr *postgrest.Client, cfg Config, log *slog.Logger) *Poller {
	if log == nil {
		log = slog.Default()
	}
	every := cfg.PollEvery
	if every <= 0 {
		every = defaultPollInterval
	}
	return &Poller{
		pr:        pr,
		http:      &http.Client{Timeout: 15 * time.Second},
		rsaSigner: strings.TrimRight(strings.TrimSpace(cfg.RSASignerURL), "/"),
		log:       log,
		interval:  every,
	}
}

func (p *Poller) Run(ctx context.Context) {
	p.log.Info("payment poller started", "every", p.interval)
	t := time.NewTicker(p.interval)
	defer t.Stop()
	p.tick(ctx)
	for {
		select {
		case <-ctx.Done():
			p.log.Info("payment poller stopped")
			return
		case <-t.C:
			p.tick(ctx)
		}
	}
}

func (p *Poller) tick(ctx context.Context) {
	providers, err := p.loadProviderConfig(ctx)
	if err != nil {
		p.log.Warn("payment poller: load config", "err", err)
		return
	}
	txns, err := p.listPending(ctx)
	if err != nil {
		p.log.Warn("payment poller: list pending", "err", err)
		return
	}
	if len(txns) == 0 {
		return
	}
	var updated int
	for _, txn := range txns {
		status, ok := p.resolveStatus(ctx, providers, txn)
		if !ok || status == "" || strings.EqualFold(status, txn.Status) {
			continue
		}
		if err := p.patchStatus(ctx, txn.ID, status); err != nil {
			p.log.Warn("payment poller: patch", "id", txn.ID, "err", err)
			continue
		}
		updated++
	}
	if updated > 0 {
		p.log.Info("payment poller tick", "pending", len(txns), "updated", updated)
	}
}

type providerConfig struct {
	PayOS     payOSConfig
	Stripe    stripeConfig
	PayerMax  payerMaxConfig
}

type payOSConfig struct {
	ClientID     string
	ClientSecret string
}

type stripeConfig struct {
	SecretKey string
}

type payerMaxConfig struct {
	AppID      string
	MerchantNo string
	BaseURL    string
	PrivateKey string
}

type txnRow struct {
	ID       int64           `json:"id"`
	Provider string          `json:"provider"`
	Status   string          `json:"status"`
	Data     json.RawMessage `json:"data"`
	ExpireAt time.Time       `json:"expire_at"`
}

func (p *Poller) loadProviderConfig(ctx context.Context) (providerConfig, error) {
	var rows []struct {
		Name  string          `json:"name"`
		Value json.RawMessage `json:"value"`
	}
	q := url.Values{}
	q.Set("select", "name,value")
	q.Set("name", "in.(payos,stripe,payermax)")
	if err := p.pr.Select(ctx, "constant", q, &rows); err != nil {
		return providerConfig{}, err
	}
	var out providerConfig
	for _, row := range rows {
		switch row.Name {
		case "payos":
			var v struct {
				ClientID     string `json:"client_id"`
				ClientSecret string `json:"client_secret"`
			}
			_ = json.Unmarshal(row.Value, &v)
			out.PayOS = payOSConfig{ClientID: v.ClientID, ClientSecret: v.ClientSecret}
		case "stripe":
			var v struct {
				SecretKey string `json:"secret_key"`
			}
			_ = json.Unmarshal(row.Value, &v)
			out.Stripe = stripeConfig{SecretKey: v.SecretKey}
		case "payermax":
			var v struct {
				AppID      string `json:"app_id"`
				MerchantNo string `json:"merchant_no"`
				BaseURL    string `json:"base_url"`
				PrivateKey string `json:"private_key"`
			}
			_ = json.Unmarshal(row.Value, &v)
			out.PayerMax = payerMaxConfig{
				AppID: v.AppID, MerchantNo: v.MerchantNo, BaseURL: strings.TrimRight(v.BaseURL, "/"), PrivateKey: v.PrivateKey,
			}
		}
	}
	return out, nil
}

func (p *Poller) listPending(ctx context.Context) ([]txnRow, error) {
	var rows []txnRow
	q := url.Values{}
	q.Set("select", "id,provider,status,data,expire_at")
	q.Set("status", "in.(PENDING,_PENDING)")
	q.Set("expire_at", "gt."+time.Now().Add(-10*time.Minute).UTC().Format(time.RFC3339))
	if err := p.pr.Select(ctx, "transactions", q, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

func (p *Poller) resolveStatus(ctx context.Context, cfg providerConfig, txn txnRow) (string, bool) {
	switch strings.ToUpper(strings.TrimSpace(txn.Provider)) {
	case "PAYOS":
		return p.pollPayOS(ctx, cfg.PayOS, txn)
	case "STRIPE":
		return p.pollStripe(ctx, cfg.Stripe, txn)
	case "PAYERMAX":
		return p.pollPayerMax(ctx, cfg.PayerMax, txn)
	default:
		return "", false
	}
}

func (p *Poller) pollPayOS(ctx context.Context, cfg payOSConfig, txn txnRow) (string, bool) {
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return "", false
	}
	var data map[string]any
	if err := json.Unmarshal(txn.Data, &data); err != nil {
		return "", false
	}
	inner, _ := data["data"].(map[string]any)
	orderCode, _ := inner["orderCode"].(string)
	if orderCode == "" {
		return "", false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api-merchant.payos.vn/v2/payment-requests/"+url.PathEscape(orderCode), nil)
	if err != nil {
		return "", false
	}
	req.Header.Set("x-client-id", cfg.ClientID)
	req.Header.Set("x-api-key", cfg.ClientSecret)
	resp, err := p.http.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			_ = resp.Body.Close()
		}
		return "", false
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", false
	}
	var parsed struct {
		Data struct {
			Status string `json:"status"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", false
	}
	if parsed.Data.Status == "" {
		return "", false
	}
	return strings.ToUpper(parsed.Data.Status), true
}

func (p *Poller) pollStripe(ctx context.Context, cfg stripeConfig, txn txnRow) (string, bool) {
	if cfg.SecretKey == "" {
		return "", false
	}
	var data map[string]any
	if err := json.Unmarshal(txn.Data, &data); err != nil {
		return "", false
	}
	sessionID, _ := data["id"].(string)
	if sessionID == "" {
		return "", false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.stripe.com/v1/checkout/sessions/"+url.PathEscape(sessionID), nil)
	if err != nil {
		return "", false
	}
	req.Header.Set("Authorization", "Bearer "+cfg.SecretKey)
	resp, err := p.http.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			_ = resp.Body.Close()
		}
		return "", false
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", false
	}
	var parsed struct {
		PaymentStatus string `json:"payment_status"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", false
	}
	if strings.EqualFold(parsed.PaymentStatus, "paid") {
		return "PAID", true
	}
	return "PENDING", true
}

func (p *Poller) pollPayerMax(ctx context.Context, cfg payerMaxConfig, txn txnRow) (string, bool) {
	if cfg.AppID == "" || cfg.MerchantNo == "" || cfg.BaseURL == "" {
		return "", false
	}
	var data map[string]any
	if err := json.Unmarshal(txn.Data, &data); err != nil {
		return "", false
	}
	inner, _ := data["data"].(map[string]any)
	outTradeNo, _ := inner["outTradeNo"].(string)
	if outTradeNo == "" {
		return "", false
	}
	reqTime := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	reqBody := map[string]any{
		"version": "1.4", "keyVersion": "1", "requestTime": reqTime,
		"appId": cfg.AppID, "merchantNo": cfg.MerchantNo,
		"data": map[string]any{"outTradeNo": outTradeNo},
	}
	bodyBytes, _ := json.Marshal(reqBody)
	sign, err := p.signPayerMax(ctx, string(bodyBytes), cfg.PrivateKey)
	if err != nil {
		return "", false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.BaseURL+"/orderQuery", bytes.NewReader(bodyBytes))
	if err != nil {
		return "", false
	}
	req.Header.Set("Content-Type", "application/json;charset=utf-8")
	req.Header.Set("sign", sign)
	resp, err := p.http.Do(req)
	if err != nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if resp != nil {
			_ = resp.Body.Close()
		}
		return "", false
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", false
	}
	var parsed struct {
		Code string `json:"code"`
		Data struct {
			Status string `json:"status"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil || parsed.Code != "APPLY_SUCCESS" {
		return "", false
	}
	switch parsed.Data.Status {
	case "SUCCESS":
		return "PAID", true
	case "FAILED", "CLOSED":
		return "CANCEL", true
	default:
		return "", false
	}
}

func (p *Poller) signPayerMax(ctx context.Context, content, privateKey string) (string, error) {
	if p.rsaSigner != "" {
		payload, _ := json.Marshal(map[string]string{"content": content, "private_key": privateKey})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.rsaSigner+"/sign-rsa", bytes.NewReader(payload))
		if err != nil {
			return "", err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := p.http.Do(req)
		if err != nil {
			return "", err
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return "", fmt.Errorf("rsa signer: %s", body)
		}
		var out struct {
			Signature string `json:"signature"`
			Error     string `json:"error"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			return "", err
		}
		if out.Error != "" {
			return "", fmt.Errorf("%s", out.Error)
		}
		return out.Signature, nil
	}
	return "", fmt.Errorf("payment.rsaSignerURL not configured")
}

func (p *Poller) patchStatus(ctx context.Context, id int64, status string) error {
	q := url.Values{}
	q.Set("id", fmt.Sprintf("eq.%d", id))
	return p.pr.Update(ctx, "transactions", q, map[string]any{"status": status}, nil)
}
