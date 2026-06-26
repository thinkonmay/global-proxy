// Package registry provides a provider registry and config mapping from gateway configuration.
package registry

import (
	"strings"

	gwconfig "github.com/thinkonmay/global-proxy/api/config"
	payment "github.com/thinkonmay/global-proxy/api/pkg/payment"
	"github.com/thinkonmay/global-proxy/api/pkg/payment/payermax"
	"github.com/thinkonmay/global-proxy/api/pkg/payment/payos"
	"github.com/thinkonmay/global-proxy/api/pkg/payment/stripe"
)

// Config types for each provider.
type StripeConfig struct {
	SecretKey     string
	WebhookSecret string
}
type PayOSConfig struct{ ClientID, ClientSecret, ChecksumKey string }
type PayerMaxConfig struct{ AppID, MerchantNo, BaseURL, PrivateKey, PublicKey string }

// Config holds provider credentials for the registry.
type Config struct {
	Stripe   StripeConfig
	PayOS    PayOSConfig
	PayerMax PayerMaxConfig
}

// ConfigFromGateway converts a gateway config Payment block to a registry Config.
func ConfigFromGateway(p gwconfig.Payment) Config {
	return Config{
		Stripe:   StripeConfig{SecretKey: p.Stripe.SecretKey, WebhookSecret: p.Stripe.WebhookSecret},
		PayOS:    PayOSConfig{ClientID: p.PayOS.ClientID, ClientSecret: p.PayOS.ClientSecret, ChecksumKey: p.PayOS.ChecksumKey},
		PayerMax: PayerMaxConfig{AppID: p.PayerMax.AppID, MerchantNo: p.PayerMax.MerchantNo, BaseURL: p.PayerMax.BaseURL, PrivateKey: p.PayerMax.PrivateKey, PublicKey: p.PayerMax.PublicKey},
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
