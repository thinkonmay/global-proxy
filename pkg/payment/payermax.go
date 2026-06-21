package payment

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	payermaxsdk "github.com/shareit-payermax/payermax-server-sdk-go/payermax"
)

func normalizePayerMaxBaseURL(base string) string {
	base = strings.TrimSpace(base)
	if base == "" {
		return payermaxsdk.Prod
	}
	return strings.TrimRight(base, "/") + "/"
}

func payerMaxCountry(currency string) string {
	if strings.EqualFold(currency, "USD") {
		return "US"
	}
	return "ID"
}

func payerMaxOrderPayload(txn txnRow, amount float64, currency string) (string, error) {
	cur := strings.ToUpper(strings.TrimSpace(currency))
	if cur != "USD" && cur != "IDR" {
		return "", fmt.Errorf("payermax only supports USD or IDR")
	}
	data, err := json.Marshal(map[string]string{
		"userId":           "U10001",
		"integrate":        "Hosted_Checkout",
		"outTradeNo":       "P" + strconv.FormatInt(txn.ID, 10),
		"totalAmount":      strconv.FormatInt(int64(math.Round(amount)), 10),
		"currency":         cur,
		"country":          payerMaxCountry(cur),
		"subject":          "Thinkmay Service",
		"body":             "Order # " + strconv.FormatInt(txn.ID, 10),
		"frontCallbackUrl": "https://thinkmay.net/id/payment/success?" + metadataQuery(txn.Metadata),
	})
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func parsePayerMaxOutTradeNo(raw json.RawMessage) (string, error) {
	var top map[string]any
	if err := json.Unmarshal(raw, &top); err != nil {
		return "", err
	}
	inner, _ := top["data"].(map[string]any)
	if inner == nil {
		return "", fmt.Errorf("payermax response missing data")
	}
	outTradeNo, _ := inner["outTradeNo"].(string)
	if outTradeNo == "" {
		return "", fmt.Errorf("payermax response missing outTradeNo")
	}
	return outTradeNo, nil
}

func mapPayerMaxStatus(status string) (string, bool) {
	switch status {
	case "SUCCESS":
		return "PAID", true
	case "FAILED", "CLOSED":
		return "CANCEL", true
	default:
		return "", false
	}
}

func parsePayerMaxQueryResponse(resp string) (string, bool, error) {
	var parsed struct {
		Code string `json:"code"`
		Data struct {
			Status string `json:"status"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(resp), &parsed); err != nil {
		return "", false, err
	}
	if parsed.Code != "APPLY_SUCCESS" {
		return "", false, fmt.Errorf("payermax query: %s", resp)
	}
	mapped, ok := mapPayerMaxStatus(parsed.Data.Status)
	return mapped, ok, nil
}

func (s *Service) payerMaxClient(cfg payerMaxConfig) (*payermaxsdk.Client, error) {
	if cfg.AppID == "" || cfg.MerchantNo == "" {
		return nil, fmt.Errorf("payermax app_id/merchant_no not configured")
	}
	if cfg.PrivateKey == "" {
		return nil, fmt.Errorf("payermax private_key not configured")
	}
	if cfg.PublicKey == "" {
		return nil, fmt.Errorf("payermax public_key not configured (required for SDK response verification)")
	}
	return payermaxsdk.CreateClient(
		cfg.AppID,
		cfg.MerchantNo,
		cfg.PrivateKey,
		cfg.PublicKey,
		"", "",
		payermaxsdk.ClientSettings{
			BaseUrl:       normalizePayerMaxBaseURL(cfg.BaseURL),
			ClientTimeout: 15 * time.Second,
		},
	)
}
