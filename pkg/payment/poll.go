package payment

import (
	"context"
	"encoding/json"
	"strings"

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
	client, err := s.payerMaxClient(cfg)
	if err != nil {
		return "", false
	}
	outTradeNo, err := parsePayerMaxOutTradeNo(txn.Data)
	if err != nil {
		return "", false
	}
	payload, err := json.Marshal(map[string]string{"outTradeNo": outTradeNo})
	if err != nil {
		return "", false
	}
	resp, err := client.Send("orderQuery", string(payload))
	if err != nil {
		return "", false
	}
	status, ok, err := parsePayerMaxQueryResponse(resp)
	if err != nil || !ok {
		return "", false
	}
	return status, true
}
