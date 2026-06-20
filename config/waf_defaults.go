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
		"/rest/v1/rpc/get_depotkey",
		"/rest/v1/rpc/search_stores",
		"/rest/v1/rpc/local_version_control_v1",
		"/rest/v1/rpc/keepalive_v1",
		"/rest/v1/rpc/sync_volume_data_v1",
	}
}
