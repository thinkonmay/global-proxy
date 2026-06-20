package config

// Admin configures B12 multi-host internal access (IP + email + Redis OTP SSO).
type Admin struct {
	Enabled         bool         `mapstructure:"enabled"`
	AllowedIPs      []string     `mapstructure:"allowedIPs"`
	AllowedEmails   []string     `mapstructure:"allowedEmails"`
	CookieDomain    string       `mapstructure:"cookieDomain"`
	SessionTTLHours int          `mapstructure:"sessionTTLHours"`
	OTPTTLMinutes   int          `mapstructure:"otpTTLMinutes"`
	SigningSecret   string       `mapstructure:"signingSecret"`
	BasicAuthUser   string       `mapstructure:"basicAuthUser"`
	BasicAuthPass   string       `mapstructure:"basicAuthPassword"`
	Redis           Redis        `mapstructure:"redis"`
	Resend          Resend       `mapstructure:"resend"`
	Hosts           AdminHosts   `mapstructure:"hosts"`
	Ingest          AdminIngest  `mapstructure:"ingest"`
	Upstreams       AdminUpstreams `mapstructure:"upstreams"`
}

type Redis struct {
	URL string `mapstructure:"url"`
}

type Resend struct {
	APIKey string `mapstructure:"apiKey"`
	From   string `mapstructure:"from"`
}

type AdminHosts struct {
	Public    string `mapstructure:"public"`
	Studio    string `mapstructure:"studio"`
	Analytics string `mapstructure:"analytics"`
	Grafana   string `mapstructure:"grafana"`
}

type AdminIngest struct {
	AnalyticsPrefix string `mapstructure:"analyticsPrefix"`
}

type AdminUpstreams struct {
	Studio        string `mapstructure:"studio"`
	RybbitClient  string `mapstructure:"rybbitClient"`
	RybbitBackend string `mapstructure:"rybbitBackend"`
	Grafana       string `mapstructure:"grafana"`
}
