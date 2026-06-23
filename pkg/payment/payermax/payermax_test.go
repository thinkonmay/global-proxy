// Package payermax implements tests for the payment.Client interface for the PayerMax provider.
package payermax

import (
	"testing"
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
