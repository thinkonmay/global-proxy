package payment

import (
	"encoding/json"
	"testing"
)

func TestNormalizePayerMaxBaseURL(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"https://pay-gate.payermax.com/aggregate-pay/api/gateway", "https://pay-gate.payermax.com/aggregate-pay/api/gateway/"},
		{"https://pay-gate.payermax.com/aggregate-pay/api/gateway/", "https://pay-gate.payermax.com/aggregate-pay/api/gateway/"},
		{"", "https://pay-gate.payermax.com/aggregate-pay/api/gateway/"},
	}
	for _, tc := range tests {
		if got := normalizePayerMaxBaseURL(tc.in); got != tc.want {
			t.Fatalf("normalizePayerMaxBaseURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestParsePayerMaxOutTradeNo(t *testing.T) {
	raw := json.RawMessage(`{"code":"APPLY_SUCCESS","data":{"outTradeNo":"P42","redirectUrl":"https://example.com"}}`)
	got, err := parsePayerMaxOutTradeNo(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got != "P42" {
		t.Fatalf("outTradeNo = %q, want P42", got)
	}
}

func TestMapPayerMaxStatus(t *testing.T) {
	if status, ok := mapPayerMaxStatus("SUCCESS"); !ok || status != "PAID" {
		t.Fatalf("SUCCESS => %q %v, want PAID true", status, ok)
	}
	if status, ok := mapPayerMaxStatus("CLOSED"); !ok || status != "CANCEL" {
		t.Fatalf("CLOSED => %q %v, want CANCEL true", status, ok)
	}
	if _, ok := mapPayerMaxStatus("PENDING"); ok {
		t.Fatal("PENDING should not map")
	}
}

func TestPayerMaxOrderPayload(t *testing.T) {
	payload, err := payerMaxOrderPayload(txnRow{
		ID:       7,
		Currency: "USD",
		Metadata: json.RawMessage(`{"foo":"bar"}`),
	}, 12.6, "USD")
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(payload), &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["outTradeNo"] != "P7" {
		t.Fatalf("outTradeNo = %q", m["outTradeNo"])
	}
	if m["totalAmount"] != "13" {
		t.Fatalf("totalAmount = %q, want string 13", m["totalAmount"])
	}
	if m["country"] != "US" {
		t.Fatalf("country = %q, want US for USD", m["country"])
	}
	if m["integrate"] != "Hosted_Checkout" {
		t.Fatalf("integrate = %q", m["integrate"])
	}
}
