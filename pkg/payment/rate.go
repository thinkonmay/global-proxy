package payment

import (
	"context"
	"fmt"
	"math"
	"net/url"
	"strings"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

// minorUnitExponent reports the number of fractional digits a currency uses.
// USD/EUR = 2; VND/IDR have no minor unit = 0.
func minorUnitExponent(currency string) int {
	switch strings.ToUpper(currency) {
	case "VND", "IDR", "JPY":
		return 0
	default:
		return 2
	}
}

// ToMoney converts a system-credit amount into provider minor units.
// majorAmount = systemCredit / rateToSystemCredit; minor = round(major * 10^exp).
func ToMoney(systemCredit float64, currency string, rateToSystemCredit float64) Money {
	major := systemCredit / rateToSystemCredit
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
