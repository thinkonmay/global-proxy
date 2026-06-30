package billing

import (
	"math"
	"testing"
)

// TestComputePlanDeposit verifies the server-side deposit sizing mirrors the website
// IdentifyAmount: wallet balance covers the plan then addons; the deposit funds only the
// shortfall; the plan portion is priced from the catalog fiat price and the addon portion
// converted at the FX rate. plan2 fixtures: credit 299, USD price 12 (rate 25), VND price
// 299000 (rate 0.001).
func TestComputePlanDeposit(t *testing.T) {
	const eps = 1e-6
	cases := []struct {
		name       string
		in         planDepositInput
		wantCharge float64
		wantCredit int64
	}{
		{
			name:       "usd no deduction full price",
			in:         planDepositInput{PlanCredit: 299, PriceMajor: 12, AddonCredit: 0, Balance: 1000, Rate: 25, PocketDeduct: false},
			wantCharge: 12,
			wantCredit: 299,
		},
		{
			name:       "vnd no deduction exact",
			in:         planDepositInput{PlanCredit: 299, PriceMajor: 299000, AddonCredit: 0, Balance: 0, Rate: 0.001, PocketDeduct: false},
			wantCharge: 299000,
			wantCredit: 299,
		},
		{
			name:       "deduction fully covered -> zero",
			in:         planDepositInput{PlanCredit: 299, PriceMajor: 12, AddonCredit: 0, Balance: 500, Rate: 25, PocketDeduct: true},
			wantCharge: 0,
			wantCredit: 0,
		},
		{
			name:       "deduction partial plan",
			in:         planDepositInput{PlanCredit: 299, PriceMajor: 12, AddonCredit: 0, Balance: 100, Rate: 25, PocketDeduct: true},
			wantCharge: 12 * 199.0 / 299.0,
			wantCredit: 199,
		},
		{
			name:       "addon adds to charge and credit",
			in:         planDepositInput{PlanCredit: 299, PriceMajor: 12, AddonCredit: 50, Balance: 0, Rate: 25, PocketDeduct: true},
			wantCharge: 12 + 50.0/25.0, // plan fiat 12 + addon fiat 2
			wantCredit: 349,
		},
		{
			name:       "deduction covers plan, partially covers addon",
			in:         planDepositInput{PlanCredit: 299, PriceMajor: 12, AddonCredit: 100, Balance: 349, Rate: 25, PocketDeduct: true},
			wantCharge: 50.0 / 25.0, // plan fully covered; addon short 50 -> fiat 2
			wantCredit: 50,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotCharge, gotCredit := computePlanDeposit(tc.in)
			if gotCredit != tc.wantCredit {
				t.Errorf("credit = %d, want %d", gotCredit, tc.wantCredit)
			}
			if math.Abs(gotCharge-tc.wantCharge) > eps {
				t.Errorf("charge = %v, want %v", gotCharge, tc.wantCharge)
			}
		})
	}
}
