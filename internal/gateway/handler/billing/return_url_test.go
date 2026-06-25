package billing

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

func TestReturnURLForTxn_DefaultBaseTagsTxnID(t *testing.T) {
	got := returnURLForTxn(txnRow{ID: 42})
	if !strings.HasPrefix(got, "https://thinkmay.net?") {
		t.Fatalf("want default base, got %q", got)
	}
	u, _ := url.Parse(got)
	if u.Query().Get("transaction_id") != "42" {
		t.Fatalf("transaction_id = %q, want 42", u.Query().Get("transaction_id"))
	}
}

func TestReturnURLForTxn_HonorsAbsoluteReturnURL(t *testing.T) {
	meta, _ := json.Marshal(map[string]any{
		"return_url": "https://app.example.com/en/payment/success",
		"plan_name":  "month1",
	})
	got := returnURLForTxn(txnRow{ID: 7, Metadata: meta})
	u, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if u.Host != "app.example.com" || u.Path != "/en/payment/success" {
		t.Fatalf("base not honored: %q", got)
	}
	q := u.Query()
	if q.Get("transaction_id") != "7" {
		t.Fatalf("transaction_id = %q", q.Get("transaction_id"))
	}
	if q.Get("plan_name") != "month1" {
		t.Fatalf("plan_name = %q", q.Get("plan_name"))
	}
	if q.Get("return_url") != "" {
		t.Fatalf("return_url leaked into query: %q", got)
	}
}

func TestReturnURLForTxn_RejectsNonAbsoluteReturnURL(t *testing.T) {
	meta, _ := json.Marshal(map[string]any{"return_url": "javascript:alert(1)"})
	got := returnURLForTxn(txnRow{ID: 1, Metadata: meta})
	if !strings.HasPrefix(got, "https://thinkmay.net") {
		t.Fatalf("non-absolute return_url should fall back to default base, got %q", got)
	}
}

func TestCancelURLForTxn_HonorsCancelURLNoTxnID(t *testing.T) {
	meta, _ := json.Marshal(map[string]any{
		"return_url": "https://app.example.com/en/payment/success",
		"cancel_url": "https://app.example.com/en/payment",
	})
	got := cancelURLForTxn(txnRow{ID: 5, Metadata: meta})
	u, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if u.Host != "app.example.com" || u.Path != "/en/payment" {
		t.Fatalf("cancel base not honored: %q", got)
	}
	// cancel URL carries no transaction_id (nothing to verify on cancel)
	if u.Query().Get("transaction_id") != "" {
		t.Fatalf("cancel url should not carry transaction_id: %q", got)
	}
}

func TestReturnURLForTxn_StripsCancelURLFromQuery(t *testing.T) {
	meta, _ := json.Marshal(map[string]any{
		"return_url": "https://app.example.com/en/payment/success",
		"cancel_url": "https://app.example.com/en/payment",
	})
	got := returnURLForTxn(txnRow{ID: 9, Metadata: meta})
	if strings.Contains(got, "cancel_url") {
		t.Fatalf("cancel_url leaked into success query: %q", got)
	}
}
