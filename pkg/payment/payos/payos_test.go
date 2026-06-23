package payos

import (
	"testing"

	payment "github.com/thinkonmay/global-proxy/api/pkg/payment"
)

func TestMapStatusCanonical(t *testing.T) {
	cases := map[string]payment.Status{
		"PAID":      payment.StatusSuccess,
		"CANCELLED": payment.StatusCanceled, // const value must equal "cancelled"
		"EXPIRED":   payment.StatusCanceled,
		"PENDING":   payment.StatusPending,
	}
	for in, want := range cases {
		if got := mapStatus(in); got != want {
			t.Fatalf("mapStatus(%q) = %q, want %q", in, got, want)
		}
	}
	if string(payment.StatusCanceled) != "cancelled" {
		t.Fatalf("StatusCanceled = %q, want cancelled", payment.StatusCanceled)
	}
}
