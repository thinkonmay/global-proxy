// Package payermax implements the payment.Client interface for the PayerMax provider.
package payermax

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	payment "github.com/thinkonmay/global-proxy/api/pkg/payment"
	"github.com/thinkonmay/global-proxy/api/pkg/router"
)

// prodBaseURL is the PayerMax production gateway, used when Config.BaseURL is empty.
const prodBaseURL = "https://pay-gate.payermax.com/aggregate-pay/api/gateway/"

// Config holds PayerMax credentials and endpoint; mirrors the legacy payerMaxConfig.
// PrivateKey/PublicKey accept PEM or bare base64 (PKCS#1/PKCS#8/PKIX). PublicKey is
// optional and, when set, verifies the response signature on successful replies.
type Config struct {
	AppID      string
	MerchantNo string
	BaseURL    string
	PrivateKey string
	PublicKey  string
}

// Client is a PayerMax payment provider.
type Client struct {
	cfg        Config
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	keyErr     error
	http       *http.Client
}

var _ payment.Client = (*Client)(nil)

// New constructs a PayerMax payment client, parsing keys up front. Key errors are
// deferred to Charge/GetCharge so an unconfigured provider does not fail at startup.
func New(cfg Config) payment.Client {
	c := &Client{cfg: cfg, http: &http.Client{Timeout: 15 * time.Second}}
	if cfg.PrivateKey == "" {
		c.keyErr = fmt.Errorf("payermax private_key not configured")
		return c
	}
	if c.privateKey, c.keyErr = parsePrivateKey(cfg.PrivateKey); c.keyErr != nil {
		return c
	}
	if cfg.PublicKey != "" {
		c.publicKey, c.keyErr = parsePublicKey(cfg.PublicKey)
	}
	return c
}

// Name identifies the provider for registry lookup.
func (c *Client) Name() string { return "payermax" }

// baseURL returns the configured endpoint (trailing slash enforced) or the prod default.
func (c *Client) baseURL() string {
	if b := strings.TrimSpace(c.cfg.BaseURL); b != "" {
		return strings.TrimRight(b, "/") + "/"
	}
	return prodBaseURL
}

// country maps a currency to its PayerMax country code (USD→US, else ID).
func country(currency string) string {
	if strings.EqualFold(currency, "USD") {
		return "US"
	}
	return "ID"
}

// orderFields builds the orderAndPay request fields for a charge. When args.Method is set
// it adds targetOrg to pre-select a specific e-wallet (e.g. "OVO"/"DANA"); otherwise the
// hosted checkout page lets the user choose.
func orderFields(args payment.ChargeParams, cur, outTradeNo string) map[string]string {
	fields := map[string]string{
		"userId":           "U10001",
		"integrate":        "Hosted_Checkout",
		"outTradeNo":       outTradeNo,
		"totalAmount":      args.Money.Major(),
		"currency":         cur,
		"country":          country(cur),
		"subject":          "Thinkmay Service",
		"body":             "Order # " + args.IdempotencyKey,
		"frontCallbackUrl": args.ReturnURL,
	}
	if m := strings.ToUpper(strings.TrimSpace(args.Method)); m != "" {
		fields["targetOrg"] = m
	}
	return fields
}

// send wraps data in the PayerMax envelope, RSA-signs the body into the "sign" header,
// POSTs to apiName, and returns the raw response. On APPLY_SUCCESS it verifies the
// response signature when a public key is configured.
func (c *Client) send(ctx context.Context, apiName string, data map[string]string) (json.RawMessage, error) {
	if c.keyErr != nil {
		return nil, c.keyErr
	}
	if c.cfg.AppID == "" || c.cfg.MerchantNo == "" {
		return nil, fmt.Errorf("payermax app_id/merchant_no not configured")
	}

	body, err := json.Marshal(map[string]any{
		"version":     "1.4",
		"keyVersion":  "1",
		"requestTime": time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		"appId":       c.cfg.AppID,
		"merchantNo":  c.cfg.MerchantNo,
		"data":        data,
	})
	if err != nil {
		return nil, err
	}

	sign, err := signRSA(body, c.privateKey)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL()+apiName, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json;charset=utf-8")
	req.Header.Set("sign", sign)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if c.publicKey != nil {
		var head struct {
			Code string `json:"code"`
		}
		if json.Unmarshal(respBody, &head) == nil && head.Code == "APPLY_SUCCESS" {
			if err := verifyRSA(respBody, resp.Header.Get("sign"), c.publicKey); err != nil {
				return nil, fmt.Errorf("payermax response signature: %w", err)
			}
		}
	}
	return json.RawMessage(respBody), nil
}

// Charge initiates a hosted-checkout charge via PayerMax orderAndPay.
func (c *Client) Charge(ctx context.Context, args payment.ChargeParams) (payment.Charge, error) {
	cur := strings.ToUpper(strings.TrimSpace(args.Money.Currency))
	if cur != "USD" && cur != "IDR" {
		return payment.Charge{}, fmt.Errorf("payermax only supports USD or IDR")
	}

	outTradeNo := "P" + args.IdempotencyKey
	resp, err := c.send(ctx, "orderAndPay", orderFields(args, cur, outTradeNo))
	if err != nil {
		return payment.Charge{}, err
	}

	redirectURL, err := parseRedirectURL(resp)
	if err != nil {
		return payment.Charge{}, err
	}

	return payment.Charge{
		ID:          outTradeNo,
		Status:      payment.StatusPending,
		RedirectURL: redirectURL,
		Detail:      resp,
	}, nil
}

// GetCharge fetches the current state of a charge; id is the PayerMax outTradeNo.
func (c *Client) GetCharge(ctx context.Context, id string) (payment.Charge, error) {
	resp, err := c.send(ctx, "orderQuery", map[string]string{"outTradeNo": id})
	if err != nil {
		return payment.Charge{}, err
	}

	var parsed struct {
		Code string `json:"code"`
		Data struct {
			Status string `json:"status"`
		} `json:"data"`
	}
	if err := json.Unmarshal(resp, &parsed); err != nil {
		return payment.Charge{}, err
	}
	if parsed.Code != "APPLY_SUCCESS" {
		return payment.Charge{}, fmt.Errorf("payermax query: %s", resp)
	}

	return payment.Charge{ID: id, Status: mapStatus(parsed.Data.Status)}, nil
}

// mapStatus maps a PayerMax order status to the normalized payment status.
func mapStatus(s string) payment.Status {
	switch s {
	case "SUCCESS":
		return payment.StatusSuccess
	case "FAILED", "CLOSED":
		return payment.StatusCanceled
	default:
		return payment.StatusPending
	}
}

// parseRedirectURL extracts the redirect URL from the orderAndPay response.
func parseRedirectURL(resp []byte) (string, error) {
	var parsed struct {
		Code string `json:"code"`
		Data struct {
			RedirectURL string `json:"redirectUrl"`
		} `json:"data"`
	}
	if err := json.Unmarshal(resp, &parsed); err != nil {
		return "", err
	}
	if parsed.Code != "APPLY_SUCCESS" {
		return "", fmt.Errorf("payermax checkout failed: %s", resp)
	}
	if parsed.Data.RedirectURL == "" {
		return "", fmt.Errorf("payermax: empty redirectUrl in %s", resp)
	}
	return parsed.Data.RedirectURL, nil
}

// signRSA returns the base64 RSA-SHA256 (PKCS#1 v1.5) signature of body.
func signRSA(body []byte, key *rsa.PrivateKey) (string, error) {
	h := sha256.Sum256(body)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// verifyRSA checks a base64 RSA-SHA256 (PKCS#1 v1.5) signature over body.
func verifyRSA(body []byte, sign string, key *rsa.PublicKey) error {
	sig, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		return fmt.Errorf("decode sign: %w", err)
	}
	h := sha256.Sum256(body)
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, h[:], sig)
}

// parsePrivateKey accepts a PEM or bare-base64 RSA key in PKCS#1 or PKCS#8.
func parsePrivateKey(s string) (*rsa.PrivateKey, error) {
	der, err := keyDER(s)
	if err != nil {
		return nil, err
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("payermax: parse private key (PKCS#1/PKCS#8): %w", err)
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("payermax: private key is not RSA")
	}
	return rk, nil
}

// parsePublicKey accepts a PEM or bare-base64 RSA key in PKIX, PKCS#1, or X.509 cert form.
func parsePublicKey(s string) (*rsa.PublicKey, error) {
	der, err := keyDER(s)
	if err != nil {
		return nil, err
	}
	if k, err := x509.ParsePKIXPublicKey(der); err == nil {
		if rk, ok := k.(*rsa.PublicKey); ok {
			return rk, nil
		}
		return nil, fmt.Errorf("payermax: public key is not RSA")
	}
	if k, err := x509.ParsePKCS1PublicKey(der); err == nil {
		return k, nil
	}
	if cert, err := x509.ParseCertificate(der); err == nil {
		if rk, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			return rk, nil
		}
	}
	return nil, fmt.Errorf("payermax: parse public key (PKIX/PKCS#1/cert) failed")
}

// keyDER returns the DER bytes of a key given as a PEM block or bare base64.
func keyDER(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "-----BEGIN") {
		block, _ := pem.Decode([]byte(s))
		if block == nil {
			return nil, fmt.Errorf("payermax: invalid PEM key")
		}
		return block.Bytes, nil
	}
	s = strings.NewReplacer("\n", "", "\r", "", " ", "").Replace(s)
	der, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("payermax: invalid base64 key: %w", err)
	}
	return der, nil
}

// Subscribe is unsupported: PayerMax recurring billing is not wired here.
func (c *Client) Subscribe(ctx context.Context, args payment.SubscribeParams) (payment.Subscription, error) {
	return payment.Subscription{}, payment.ErrNotSupported
}

// GetSubscription is unsupported for PayerMax.
func (c *Client) GetSubscription(ctx context.Context, id string) (payment.Subscription, error) {
	return payment.Subscription{}, payment.ErrNotSupported
}

// CancelSubscription is unsupported for PayerMax.
func (c *Client) CancelSubscription(ctx context.Context, id string) error {
	return payment.ErrNotSupported
}

// payermaxAck is PayerMax's required notification acknowledgement; it retries
// unless the body's code is "SUCCESS".
const payermaxAck = `{"code":"SUCCESS","msg":"Success"}`

// RegisterRoutes mounts the PayerMax payment-result webhook. The poll fallback
// still covers anything the notification misses.
func (c *Client) RegisterRoutes(g *router.Group, deliver func(ctx context.Context, e payment.Event) error) {
	g.POST("/payermax", func(w http.ResponseWriter, r *http.Request) {
		if c.publicKey == nil {
			http.Error(w, "payermax not configured", http.StatusInternalServerError)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "cannot read body", http.StatusBadRequest)
			return
		}
		// PayerMax RSA-signs the raw body into the "sign" header, same as responses.
		if err := verifyRSA(body, r.Header.Get("sign"), c.publicKey); err != nil {
			http.Error(w, "invalid signature", http.StatusBadRequest)
			return
		}

		var notif struct {
			Data struct {
				OutTradeNo string `json:"outTradeNo"`
				Status     string `json:"status"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &notif); err != nil || notif.Data.OutTradeNo == "" {
			http.Error(w, "invalid notification", http.StatusBadRequest)
			return
		}

		// Only terminal states settle; PENDING is acked and left to the poll.
		if st := mapStatus(notif.Data.Status); st != payment.StatusPending {
			// outTradeNo is "P"+txn id (see Charge); settle keys on the numeric txn id.
			if err := deliver(r.Context(), payment.Event{
				Kind:       payment.EventCharge,
				ProviderID: notif.Data.OutTradeNo,
				RefID:      strings.TrimPrefix(notif.Data.OutTradeNo, "P"),
				Status:     st,
			}); err != nil {
				http.Error(w, "failed to deliver event", http.StatusInternalServerError)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(payermaxAck))
	})
}
