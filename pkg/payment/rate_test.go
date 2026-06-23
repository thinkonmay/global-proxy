package payment_test

import (
	"testing"

	payment "github.com/thinkonmay/global-proxy/api/pkg/payment"
)

func TestToMoneyUSDMinorUnits(t *testing.T) {
	// 252 system credit, rate 12.6 credit per USD => 20.00 USD => 2000 cents
	m := payment.ToMoney(252, "USD", 12.6)
	if m.Currency != "USD" || m.Amount != 2000 {
		t.Fatalf("ToMoney = %+v, want {2000 USD}", m)
	}
}

func TestToMoneyVNDNoMinorUnits(t *testing.T) {
	// 100 system credit, rate 0.004 credit per VND => 25000 VND => 25000 (no minor unit)
	m := payment.ToMoney(100, "VND", 0.004)
	if m.Currency != "VND" || m.Amount != 25000 {
		t.Fatalf("ToMoney = %+v, want {25000 VND}", m)
	}
}
