package billing

import (
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// buildReturnURL is a test-local helper that replicates what fillCheckout does:
// resolve the return URL from request-body metadata, tagging it with the txn ID.
func buildReturnURL(meta json.RawMessage, id int64) string {
	return buildRedirectURL(meta, metaReturnURL, "transaction_id", strconv.FormatInt(id, 10))
}

// buildCancelURL is a test-local helper that replicates the cancel URL path.
func buildCancelURL(meta json.RawMessage) string {
	return buildRedirectURL(meta, metaCancelURL, "", "")
}

func TestReturnURLForTxn_DefaultBaseTagsTxnID(t *testing.T) {
	got := buildReturnURL(nil, 42)
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
	got := buildReturnURL(meta, 7)
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
	got := buildReturnURL(meta, 1)
	if !strings.HasPrefix(got, "https://thinkmay.net") {
		t.Fatalf("non-absolute return_url should fall back to default base, got %q", got)
	}
}

func TestCancelURLForTxn_HonorsCancelURLNoTxnID(t *testing.T) {
	meta, _ := json.Marshal(map[string]any{
		"return_url": "https://app.example.com/en/payment/success",
		"cancel_url": "https://app.example.com/en/payment",
	})
	got := buildCancelURL(meta)
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
	got := buildReturnURL(meta, 9)
	if strings.Contains(got, "cancel_url") {
		t.Fatalf("cancel_url leaked into success query: %q", got)
	}
}
