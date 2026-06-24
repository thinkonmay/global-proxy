package payment_test

import (
	"testing"

	payment "github.com/thinkonmay/global-proxy/api/pkg/payment"
)

func TestToMoneyUSDMinorUnits(t *testing.T) {
	// 252 system credit, rate 12.6 credit per USD => 20.00 USD => 2000 cents
	m, err := payment.ToMoney(252, "USD", 12.6)
	if err != nil {
		t.Fatal(err)
	}
	if m.Currency != "USD" || m.Amount != 2000 {
		t.Fatalf("ToMoney = %+v, want {2000 USD}", m)
	}
}

func TestToMoneyVNDNoMinorUnits(t *testing.T) {
	// 100 system credit, rate 0.004 credit per VND => 25000 VND => 25000 (no minor unit)
	m, err := payment.ToMoney(100, "VND", 0.004)
	if err != nil {
		t.Fatal(err)
	}
	if m.Currency != "VND" || m.Amount != 25000 {
		t.Fatalf("ToMoney = %+v, want {25000 VND}", m)
	}
}

func TestToMoneyRejectsNonPositiveRate(t *testing.T) {
	if _, err := payment.ToMoney(100, "USD", 0); err == nil {
		t.Fatal("expected error for zero rate")
	}
	if _, err := payment.ToMoney(100, "USD", -1); err == nil {
		t.Fatal("expected error for negative rate")
	}
}

func TestMoneyMajorString(t *testing.T) {
	cases := []struct {
		amount   int64
		currency string
		want     string
	}{
		{2000, "USD", "20.00"},
		{1205, "USD", "12.05"},
		{5, "USD", "0.05"},
		{25000, "VND", "25000"}, // 0-decimal: plain integer
		{199000, "IDR", "199000"},
	}
	for _, c := range cases {
		if got := (payment.Money{Amount: c.amount, Currency: c.currency}).Major(); got != c.want {
			t.Errorf("Money{%d %s}.Major() = %q, want %q", c.amount, c.currency, got, c.want)
		}
	}
}

// Major(Minor(x)) round-trips: FromMajor parses, Major reformats.
func TestMoneyMinorMajorRoundTrip(t *testing.T) {
	m := payment.FromMajor(12, "USD") // -> 1200 minor
	if m.Minor() != 1200 {
		t.Fatalf("Minor() = %d, want 1200", m.Minor())
	}
	if m.Major() != "12.00" {
		t.Fatalf("Major() = %q, want 12.00", m.Major())
	}
}

func TestFromMajorMinorUnits(t *testing.T) {
	if m := payment.FromMajor(12, "USD"); m.Currency != "USD" || m.Amount != 1200 {
		t.Fatalf("FromMajor USD = %+v, want {1200 USD}", m)
	}
	if m := payment.FromMajor(299000, "VND"); m.Currency != "VND" || m.Amount != 299000 {
		t.Fatalf("FromMajor VND = %+v, want {299000 VND}", m)
	}
}
