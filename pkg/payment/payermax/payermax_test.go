// Package payermax implements tests for the payment.Client interface for the PayerMax provider.
package payermax

import (
	"testing"

	payment "github.com/thinkonmay/global-proxy/api/pkg/payment"
)

func TestParseRedirectURL(t *testing.T) {
	resp := `{"code":"APPLY_SUCCESS","data":{"redirectUrl":"https://pay.x/abc","outTradeNo":"P9"}}`
	url, err := parseRedirectURL([]byte(resp))
	if err != nil {
		t.Fatal(err)
	}
	if url != "https://pay.x/abc" {
		t.Fatalf("url = %q", url)
	}
}

func TestOrderFieldsTargetOrg(t *testing.T) {
	base := payment.ChargeParams{IdempotencyKey: "9", Money: payment.Money{Amount: 1000, Currency: "IDR"}}

	// No method → no targetOrg; hosted page lets the user pick.
	if f := orderFields(base, "IDR", "P9"); f["targetOrg"] != "" {
		t.Fatalf("targetOrg should be absent, got %q", f["targetOrg"])
	}

	// Method is normalized to upper-case and routed to targetOrg.
	withMethod := base
	withMethod.Method = "ovo"
	if f := orderFields(withMethod, "IDR", "P9"); f["targetOrg"] != "OVO" {
		t.Fatalf("targetOrg = %q, want OVO", f["targetOrg"])
	}
}
