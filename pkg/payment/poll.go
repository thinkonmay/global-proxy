package payment

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/stripe/stripe-go/v82"
)

func (s *Service) pollPayOS(ctx context.Context, cfg payOSConfig, txn txnRow) (string, bool) {
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return "", false
	}
	client, err := s.payosClient(cfg)
	if err != nil {
		return "", false
	}
	link, err := client.PaymentRequests.Get(ctx, txn.ID)
	if err != nil || link == nil || link.Status == "" {
		return "", false
	}
	return strings.ToUpper(string(link.Status)), true
}

func (s *Service) pollStripe(ctx context.Context, cfg stripeConfig, txn txnRow) (string, bool) {
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
	sc := s.stripeClient(cfg.SecretKey)
	sess, err := sc.V1CheckoutSessions.Retrieve(ctx, sessionID, nil)
	if err != nil {
		return "", false
	}
	if sess.PaymentStatus == stripe.CheckoutSessionPaymentStatusPaid {
		return "PAID", true
	}
	return "PENDING", true
}

func (s *Service) pollPayerMax(ctx context.Context, cfg payerMaxConfig, txn txnRow) (string, bool) {
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
	if client, err := s.payermaxClient(cfg); err == nil {
		payload, _ := json.Marshal(map[string]any{"outTradeNo": outTradeNo})
		resp, err := client.Send("orderQuery", string(payload))
		if err != nil {
			return "", false
		}
		var parsed struct {
			Code string `json:"code"`
			Data struct {
				Status string `json:"status"`
			} `json:"data"`
		}
		if err := json.Unmarshal([]byte(resp), &parsed); err != nil || parsed.Code != "APPLY_SUCCESS" {
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
	return s.pollPayerMaxHTTP(ctx, cfg, outTradeNo)
}

func (s *Service) pollPayerMaxHTTP(ctx context.Context, cfg payerMaxConfig, outTradeNo string) (string, bool) {
	reqTime := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	reqBody := map[string]any{
		"version": "1.4", "keyVersion": "1", "requestTime": reqTime,
		"appId": cfg.AppID, "merchantNo": cfg.MerchantNo,
		"data": map[string]any{"outTradeNo": outTradeNo},
	}
	bodyBytes, _ := json.Marshal(reqBody)
	sign, err := s.signPayerMax(ctx, string(bodyBytes), cfg.PrivateKey)
	if err != nil {
		return "", false
	}
	base := strings.TrimRight(cfg.BaseURL, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/orderQuery", bytes.NewReader(bodyBytes))
	if err != nil {
		return "", false
	}
	req.Header.Set("Content-Type", "application/json;charset=utf-8")
	req.Header.Set("sign", sign)
	respBody, status, err := s.do(req)
	if err != nil || status < 200 || status >= 300 {
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

func (s *Service) signPayerMax(ctx context.Context, content, privateKey string) (string, error) {
	if s.rsaSigner != "" {
		payload, _ := json.Marshal(map[string]string{"content": content, "private_key": privateKey})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.rsaSigner+"/sign-rsa", bytes.NewReader(payload))
		if err != nil {
			return "", err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := s.http.Do(req)
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
