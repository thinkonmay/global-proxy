// Package registry provides a provider registry and config mapping from gateway configuration.
package registry

import (
	"strings"

	gwconfig "github.com/thinkonmay/global-proxy/api/config"
	payment "github.com/thinkonmay/global-proxy/api/pkg/payment"
	"github.com/thinkonmay/global-proxy/api/pkg/payment/payermax"
	"github.com/thinkonmay/global-proxy/api/pkg/payment/payos"
	"github.com/thinkonmay/global-proxy/api/pkg/payment/payssion"
	"github.com/thinkonmay/global-proxy/api/pkg/payment/sepay"
	"github.com/thinkonmay/global-proxy/api/pkg/payment/stripe"
)

// Config types for each provider.
type StripeConfig struct {
	SecretKey     string
	WebhookSecret string
}
type PayOSConfig struct{ ClientID, ClientSecret, ChecksumKey string }
type PayerMaxConfig struct{ AppID, MerchantNo, BaseURL, PrivateKey, PublicKey string }
type PayssionConfig struct{ APIKey, PMID, SecretKey, Link string }
type SePayConfig struct {
	MerchantID, SecretKey, IPNSecretKey, PublicBaseURL, ReturnURL string
	Sandbox                                                       bool
}

// Config holds provider credentials for the registry.
type Config struct {
	Stripe   StripeConfig
	PayOS    PayOSConfig
	PayerMax PayerMaxConfig
	Payssion PayssionConfig
	SePay    SePayConfig
}

// ConfigFromGateway converts a gateway config Payment block to a registry Config.
func ConfigFromGateway(p gwconfig.Payment) Config {
	return Config{
		Stripe:   StripeConfig{SecretKey: p.Stripe.SecretKey, WebhookSecret: p.Stripe.WebhookSecret},
		PayOS:    PayOSConfig{ClientID: p.PayOS.ClientID, ClientSecret: p.PayOS.ClientSecret, ChecksumKey: p.PayOS.ChecksumKey},
		PayerMax: PayerMaxConfig{AppID: p.PayerMax.AppID, MerchantNo: p.PayerMax.MerchantNo, BaseURL: p.PayerMax.BaseURL, PrivateKey: p.PayerMax.PrivateKey, PublicKey: p.PayerMax.PublicKey},
		Payssion: PayssionConfig{APIKey: p.Payssion.APIKey, PMID: p.Payssion.PMID, SecretKey: p.Payssion.SecretKey, Link: p.Payssion.Link},
		SePay:    SePayConfig{MerchantID: p.SePay.MerchantID, SecretKey: p.SePay.SecretKey, IPNSecretKey: p.SePay.IPNSecretKey, PublicBaseURL: p.SePay.PublicBaseURL, ReturnURL: p.SePay.ReturnURL, Sandbox: p.SePay.Sandbox},
	}
}

// Registry holds initialized provider clients keyed by name.
type Registry struct{ providers map[string]payment.Client }

// NewRegistry constructs a Registry with all providers initialized from the given config.
func NewRegistry(cfg Config) *Registry {
	r := &Registry{providers: map[string]payment.Client{}}
	r.providers["stripe"] = stripe.New(stripe.Config{SecretKey: cfg.Stripe.SecretKey, WebhookSecret: cfg.Stripe.WebhookSecret})
	r.providers["payos"] = payos.New(payos.Config{ClientID: cfg.PayOS.ClientID, ClientSecret: cfg.PayOS.ClientSecret, ChecksumKey: cfg.PayOS.ChecksumKey})
	r.providers["payermax"] = payermax.New(payermax.Config{AppID: cfg.PayerMax.AppID, MerchantNo: cfg.PayerMax.MerchantNo, BaseURL: cfg.PayerMax.BaseURL, PrivateKey: cfg.PayerMax.PrivateKey, PublicKey: cfg.PayerMax.PublicKey})
	r.providers["payssion"] = payssion.New(payssion.Config{APIKey: cfg.Payssion.APIKey, PMID: cfg.Payssion.PMID, SecretKey: cfg.Payssion.SecretKey, Link: cfg.Payssion.Link})
	r.providers["sepay"] = sepay.New(sepay.Config{MerchantID: cfg.SePay.MerchantID, SecretKey: cfg.SePay.SecretKey, IPNSecretKey: cfg.SePay.IPNSecretKey, PublicBaseURL: cfg.SePay.PublicBaseURL, ReturnURL: cfg.SePay.ReturnURL, Sandbox: cfg.SePay.Sandbox})
	return r
}

// NewRegistryWith constructs a Registry from a pre-built provider map (test seam).
func NewRegistryWith(providers map[string]payment.Client) *Registry {
	return &Registry{providers: providers}
}

// Get returns the client for the given provider name (case-insensitive) and a bool indicating if found.
func (r *Registry) Get(name string) (payment.Client, bool) {
	c, ok := r.providers[strings.ToLower(strings.TrimSpace(name))]
	return c, ok
}

// All returns a copy of every registered provider (for poll iteration).
func (r *Registry) All() map[string]payment.Client {
	out := make(map[string]payment.Client, len(r.providers))
	for k, v := range r.providers {
		out[k] = v
	}
	return out
}
