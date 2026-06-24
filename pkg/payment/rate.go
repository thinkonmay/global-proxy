package payment

import (
	"context"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

// minorUnitExponent reports the number of fractional digits a currency uses.
// USD/EUR = 2; VND/IDR have no minor unit = 0. This is the SINGLE source of
// currency precision — no other code should hardcode "/100" or "* 100".
func minorUnitExponent(currency string) int {
	switch strings.ToUpper(currency) {
	case "VND", "IDR", "JPY":
		return 0
	default:
		return 2
	}
}

// Minor returns the amount in minor units — the canonical internal value Money
// always holds. Use for providers/APIs that want integer minor units (e.g. Stripe
// cents, PayOS VND).
func (m Money) Minor() int64 { return m.Amount }

// Major formats the amount in major units as a decimal string, via the currency's
// minorUnitExponent. Zero-decimal currencies (VND/IDR/JPY) format as a plain
// integer; others get the exact fractional digits (USD 2000 -> "20.00"). No float.
// Use for providers/APIs that want major-unit amounts (e.g. PayerMax, Payssion).
func (m Money) Major() string {
	exp := minorUnitExponent(m.Currency)
	if exp == 0 {
		return strconv.FormatInt(m.Amount, 10)
	}
	factor := int64(1)
	for range exp {
		factor *= 10
	}
	sign, a := "", m.Amount
	if a < 0 {
		sign, a = "-", -a
	}
	return fmt.Sprintf("%s%d.%0*d", sign, a/factor, exp, a%factor)
}

// ToMoney converts a system-credit amount into provider minor units.
// majorAmount = systemCredit / rateToSystemCredit; minor = round(major * 10^exp).
// A non-positive rate is rejected: it would otherwise divide by zero (or flip
// sign) and produce a garbage/overflowing charge.
func ToMoney(systemCredit float64, currency string, rateToSystemCredit float64) (Money, error) {
	if rateToSystemCredit <= 0 {
		return Money{}, fmt.Errorf("payment: non-positive rate %v for %s", rateToSystemCredit, currency)
	}
	major := systemCredit / rateToSystemCredit
	factor := math.Pow(10, float64(minorUnitExponent(currency)))
	return Money{Amount: int64(math.Round(major * factor)), Currency: strings.ToUpper(currency)}, nil
}

// FromMajor converts a major-unit fiat amount into provider minor units:
// minor = round(major * 10^exp). Use when the price is an explicit fiat amount
// (e.g. a plan's per-currency catalog price), not a system-credit amount — so no
// FX rate is involved and there is no divide-by-zero path.
func FromMajor(major float64, currency string) Money {
	factor := math.Pow(10, float64(minorUnitExponent(currency)))
	return Money{Amount: int64(math.Round(major * factor)), Currency: strings.ToUpper(currency)}
}

type RateService struct{ pr *postgrest.Client }

func NewRateService(pr *postgrest.Client) *RateService { return &RateService{pr: pr} }

func (s *RateService) Load(ctx context.Context, currency string) (float64, error) {
	var rows []struct {
		Rate float64 `json:"rate_to_system_credit"`
	}
	q := url.Values{}
	q.Set("select", "rate_to_system_credit")
	q.Set("currency", "eq."+currency)
	q.Set("limit", "1")
	if err := s.pr.SelectService(ctx, "currency_rates", q, &rows); err != nil {
		return 0, err
	}
	if len(rows) == 0 || rows[0].Rate == 0 {
		return 0, fmt.Errorf("payment: unsupported currency %s", currency)
	}
	return rows[0].Rate, nil
}
