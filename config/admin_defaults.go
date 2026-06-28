package config

func mergeAdminDefaults(cfg *Config) {
	a := &cfg.Admin
	if a.Hosts.Public == "" {
		a.Hosts.Public = "thinkmay.net"
	}
	if a.Hosts.Studio == "" {
		a.Hosts.Studio = "studio.thinkmay.net"
	}
	if a.Hosts.Analytics == "" {
		a.Hosts.Analytics = "analytics.thinkmay.net"
	}
	if a.Hosts.Grafana == "" {
		a.Hosts.Grafana = "grafana.thinkmay.net"
	}
	if a.Ingest.AnalyticsPrefix == "" {
		a.Ingest.AnalyticsPrefix = "/api/"
	}
	if a.CookieDomain == "" {
		a.CookieDomain = ".thinkmay.net"
	}
	if a.SessionTTLHours <= 0 {
		a.SessionTTLHours = 8
	}
	if a.OTPTTLMinutes <= 0 {
		a.OTPTTLMinutes = 10
	}
	if a.Upstreams.Studio == "" {
		a.Upstreams.Studio = cfg.Upstreams.Studio
	}
	if a.BasicAuthEnabled {
		if a.BasicAuthUser == "" {
			a.BasicAuthUser = cfg.Supabase.DashboardUser
		}
		if a.BasicAuthPass == "" {
			a.BasicAuthPass = cfg.Supabase.DashboardPassword
		}
	} else {
		a.BasicAuthUser = ""
		a.BasicAuthPass = ""
	}
	if len(a.AllowedIPs) == 0 && len(cfg.WAF.AllowedIPs) > 0 {
		// Ops IPs often overlap catalog WAF until dedicated admin list is configured.
		a.AllowedIPs = append([]string(nil), cfg.WAF.AllowedIPs...)
	}
	mergeTLSHostsFromAdmin(cfg)
}

func mergeTLSHostsFromAdmin(cfg *Config) {
	if !cfg.TLS.Enabled {
		return
	}
	seen := make(map[string]struct{}, len(cfg.TLS.Hosts))
	for _, h := range cfg.TLS.Hosts {
		if h = trimHost(h); h != "" {
			seen[h] = struct{}{}
		}
	}
	for _, h := range []string{
		cfg.Admin.Hosts.Public,
		cfg.Admin.Hosts.Studio,
		cfg.Admin.Hosts.Analytics,
		cfg.Admin.Hosts.Grafana,
		cfg.Admin.Hosts.Litellm,
	} {
		if h = trimHost(h); h != "" {
			if _, ok := seen[h]; !ok {
				cfg.TLS.Hosts = append(cfg.TLS.Hosts, h)
				seen[h] = struct{}{}
			}
		}
	}
}

func trimHost(h string) string {
	for len(h) > 0 && (h[0] == ' ' || h[0] == '\t') {
		h = h[1:]
	}
	for len(h) > 0 && (h[len(h)-1] == ' ' || h[len(h)-1] == '\t') {
		h = h[:len(h)-1]
	}
	return h
}
