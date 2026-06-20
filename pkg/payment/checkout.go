package payment

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	payos "github.com/payOSHQ/payos-lib-golang/v2"
	"github.com/stripe/stripe-go/v82"
)

const (
	returnURL = "https://thinkmay.net"
	cancelURL = "https://thinkmay.net"
)

// FillCheckout calls the payment provider and persists transactions.data.
// Replaces legacy Postgres on_transaction_driver_v2 + get_*_data functions.
func (s *Service) FillCheckout(ctx context.Context, txnID int64) (json.RawMessage, error) {
	txn, err := s.loadTransaction(ctx, txnID)
	if err != nil {
		return nil, err
	}
	if !dataIsEmpty(txn.Data) {
		return txn.Data, nil
	}
	if strings.TrimSpace(txn.Provider) == "" {
		return nil, fmt.Errorf("transaction %d: provider not set", txnID)
	}

	cfg, err := s.loadProviderConfig(ctx)
	if err != nil {
		return nil, err
	}
	rate, err := s.loadExchangeRate(ctx, txn.Currency)
	if err != nil {
		return nil, err
	}
	displayAmount := float64(txn.Amount) / rate

	var data json.RawMessage
	switch strings.ToUpper(strings.TrimSpace(txn.Provider)) {
	case "PAYOS":
		data, err = s.createPayOS(ctx, cfg.PayOS, txn, displayAmount)
	case "STRIPE":
		data, err = s.createStripe(ctx, cfg.Stripe, txn, displayAmount)
	case "PAYERMAX":
		data, err = s.createPayerMax(ctx, cfg.PayerMax, txn, displayAmount)
	case "PAYSSION":
		data, err = s.createPayssion(ctx, cfg.Payssion, txn, displayAmount)
	default:
		return nil, fmt.Errorf("unsupported provider %q", txn.Provider)
	}
	if err != nil {
		return nil, err
	}
	if err := s.patchData(ctx, txnID, data); err != nil {
		return nil, err
	}
	return data, nil
}

func (s *Service) patchData(ctx context.Context, id int64, data json.RawMessage) error {
	q := url.Values{}
	q.Set("id", "eq."+formatID(id))
	return s.pr.Update(ctx, "transactions", q, map[string]any{"data": json.RawMessage(data)}, nil)
}

func (s *Service) createPayOS(ctx context.Context, cfg payOSConfig, txn txnRow, amount float64) (json.RawMessage, error) {
	if cfg.ClientID == "" || cfg.ClientSecret == "" || cfg.ChecksumKey == "" {
		return nil, fmt.Errorf("payos config incomplete")
	}
	client, err := s.payosClient(cfg)
	if err != nil {
		return nil, err
	}
	amt := int(math.Round(amount))
	desc := payosDescription(txn.Email, int64(amt))
	expiredAt := int(time.Now().Add(15 * time.Minute).Unix())
	buyerEmail := txn.Email
	resp, err := client.PaymentRequests.Create(ctx, payos.CreatePaymentLinkRequest{
		OrderCode:   txn.ID,
		Amount:      amt,
		Description: desc,
		CancelUrl:   cancelURL,
		ReturnUrl:   returnURL,
		BuyerEmail:  &buyerEmail,
		ExpiredAt:   &expiredAt,
		Items: []payos.PaymentLinkItem{{
			Name: "custom", Price: amt, Quantity: 1,
		}},
	})
	if err != nil {
		return nil, err
	}
	return wrapPayOSResponse(resp)
}

func (s *Service) createStripe(ctx context.Context, cfg stripeConfig, txn txnRow, amount float64) (json.RawMessage, error) {
	if cfg.SecretKey == "" {
		return nil, fmt.Errorf("stripe secret not configured")
	}
	if strings.ToUpper(txn.Currency) != "USD" {
		return nil, fmt.Errorf("stripe only supports USD")
	}
	sc := s.stripeClient(cfg.SecretKey)
	sess, err := sc.V1CheckoutSessions.Create(ctx, &stripe.CheckoutSessionCreateParams{
		Mode:                 stripe.String(string(stripe.CheckoutSessionModePayment)),
		UIMode:               stripe.String(string(stripe.CheckoutSessionUIModeEmbedded)),
		CustomerEmail:        stripe.String(txn.Email),
		RedirectOnCompletion: stripe.String(string(stripe.CheckoutSessionRedirectOnCompletionNever)),
		PaymentMethodTypes:     []*string{stripe.String("card")},
		LineItems: []*stripe.CheckoutSessionCreateLineItemParams{{
			Quantity: stripe.Int64(1),
			PriceData: &stripe.CheckoutSessionCreateLineItemPriceDataParams{
				Currency:   stripe.String(strings.ToLower(txn.Currency)),
				UnitAmount: stripe.Int64(int64(math.Round(amount * 100))),
				ProductData: &stripe.CheckoutSessionCreateLineItemPriceDataProductDataParams{
					Name: stripe.String("thinkmay"),
				},
			},
		}},
	})
	if err != nil {
		return nil, err
	}
	return json.Marshal(sess)
}

func (s *Service) createPayerMax(ctx context.Context, cfg payerMaxConfig, txn txnRow, amount float64) (json.RawMessage, error) {
	if cfg.AppID == "" || cfg.MerchantNo == "" || cfg.BaseURL == "" {
		return nil, fmt.Errorf("payermax config incomplete")
	}
	cur := strings.ToUpper(txn.Currency)
	if cur != "USD" && cur != "IDR" {
		return nil, fmt.Errorf("payermax only supports USD or IDR")
	}
	if client, err := s.payermaxClient(cfg); err == nil {
		data, _ := json.Marshal(map[string]any{
			"userId":           "U10001",
			"integrate":        "Hosted_Checkout",
			"outTradeNo":       "P" + strconv.FormatInt(txn.ID, 10),
			"totalAmount":      int64(math.Round(amount)),
			"currency":         cur,
			"country":          "ID",
			"subject":          "Thinkmay Service",
			"body":             "Order # " + strconv.FormatInt(txn.ID, 10),
			"frontCallbackUrl": "https://thinkmay.net/id/payment/success?" + metadataQuery(txn.Metadata),
		})
		resp, err := client.Send("orderAndPay", string(data))
		if err != nil {
			return nil, err
		}
		var parsed struct {
			Code string `json:"code"`
		}
		if err := json.Unmarshal([]byte(resp), &parsed); err != nil {
			return nil, err
		}
		if parsed.Code != "APPLY_SUCCESS" {
			return nil, fmt.Errorf("payermax checkout failed: %s", resp)
		}
		return json.RawMessage(resp), nil
	}
	return s.createPayerMaxHTTP(ctx, cfg, txn, amount, cur)
}

func (s *Service) createPayssion(ctx context.Context, cfg payssionConfig, txn txnRow, amount float64) (json.RawMessage, error) {
	if cfg.APIKey == "" || cfg.PMID == "" || cfg.SecretKey == "" || cfg.Link == "" {
		return nil, fmt.Errorf("payssion config incomplete")
	}
	amt := int64(math.Round(amount))
	orderID := strconv.FormatInt(txn.ID, 10)
	sigRaw := cfg.APIKey + "|" + cfg.PMID + "|" + strconv.FormatInt(amt, 10) + "|" +
		strings.ToUpper(txn.Currency) + "|" + orderID + "|" + cfg.SecretKey
	sig := fmt.Sprintf("%x", md5.Sum([]byte(sigRaw)))

	form := url.Values{}
	form.Set("api_key", cfg.APIKey)
	form.Set("api_sig", sig)
	form.Set("pm_id", cfg.PMID)
	form.Set("amount", strconv.FormatInt(amt, 10))
	form.Set("currency", strings.ToUpper(txn.Currency))
	form.Set("order_id", orderID)
	form.Set("description", payosDescription(txn.Email, amt))

	link := strings.TrimRight(cfg.Link, "/") + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, link+"payment/create", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	respBody, status, err := s.do(req)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("payssion checkout: status %d: %s", status, respBody)
	}
	var parsed struct {
		ResultCode int `json:"result_code"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, err
	}
	if parsed.ResultCode != 200 {
		return nil, fmt.Errorf("payssion checkout failed: %s", respBody)
	}
	return respBody, nil
}

func (s *Service) do(req *http.Request) ([]byte, int, error) {
	resp, err := s.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

func payosDescription(email string, amount int64) string {
	prefix := email
	if i := strings.Index(email, "@"); i >= 0 {
		prefix = email[:i]
	}
	if len(prefix) > 15 {
		prefix = prefix[:15]
	}
	return prefix + strconv.FormatInt(amount, 10)
}

func metadataQuery(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil || len(m) == 0 {
		return ""
	}
	vals := url.Values{}
	for k, v := range m {
		vals.Set(k, fmt.Sprint(v))
	}
	return vals.Encode()
}

func (s *Service) createPayerMaxHTTP(ctx context.Context, cfg payerMaxConfig, txn txnRow, amount float64, cur string) (json.RawMessage, error) {
	reqTime := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	reqData := map[string]any{
		"userId":           "U10001",
		"integrate":        "Hosted_Checkout",
		"outTradeNo":       "P" + strconv.FormatInt(txn.ID, 10),
		"totalAmount":      int64(math.Round(amount)),
		"currency":         cur,
		"country":          "ID",
		"subject":          "Thinkmay Service",
		"body":             "Order # " + strconv.FormatInt(txn.ID, 10),
		"frontCallbackUrl": "https://thinkmay.net/id/payment/success?" + metadataQuery(txn.Metadata),
	}
	reqBody := map[string]any{
		"version": "1.4", "keyVersion": "1", "requestTime": reqTime,
		"appId": cfg.AppID, "merchantNo": cfg.MerchantNo, "data": reqData,
	}
	bodyBytes, _ := json.Marshal(reqBody)
	sign, err := s.signPayerMax(ctx, string(bodyBytes), cfg.PrivateKey)
	if err != nil {
		return nil, err
	}
	base := strings.TrimRight(cfg.BaseURL, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/orderAndPay", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("sign", sign)

	respBody, status, err := s.do(req)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("payermax checkout: status %d: %s", status, respBody)
	}
	var parsed struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, err
	}
	if parsed.Code != "APPLY_SUCCESS" {
		return nil, fmt.Errorf("payermax checkout failed: %s", respBody)
	}
	return respBody, nil
}
