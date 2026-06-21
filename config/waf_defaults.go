package config

// defaultPublicReadPaths mirrors globalproxy -waf-paths (planning.md).
func defaultPublicReadPaths() []string {
	return []string{
		"/rest/v1/stores",
		"/rest/v1/addons",
		"/rest/v1/plans",
		"/rest/v1/currency_rates",
		"/rest/v1/referral",
		"/rest/v1/discounts",
		"/rest/v1/feedbacks",
		"/rest/v1/banner",
		"/rest/v1/binary_release",
		"/rest/v1/constant",
	}
}
