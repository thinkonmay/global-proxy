package billing

import (
	"net/http"
	"time"

	payment "github.com/thinkonmay/global-proxy/api/pkg/payment"
	registry "github.com/thinkonmay/global-proxy/api/pkg/payment/registry"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

const (
	billingQueryTimeout   = 5 * time.Second
	billingDepositTimeout = 30 * time.Second
)

// Handler serves /v1/billing/* typed REST (replaces /v1/rpc billing RPCs).
type Handler struct {
	pr        *postgrest.Client
	registry  *registry.Registry
	rates     *payment.RateService
	transport http.RoundTripper
}

func New(pr *postgrest.Client, rt http.RoundTripper, reg *registry.Registry, rates *payment.RateService) *Handler {
	if rt == nil {
		rt = http.DefaultTransport
	}
	return &Handler{pr: pr, registry: reg, rates: rates, transport: rt}
}

func (h *Handler) Register(mux *http.ServeMux) {
	routes := []struct {
		method string
		path   string
		fn     http.HandlerFunc
	}{
		{http.MethodGet, "/v1/billing/wallet", h.Wallet},
		{http.MethodGet, "/v1/billing/subscription", h.Subscription},
		{http.MethodGet, "/v1/billing/addon-charges", h.AddonCharges},
		{http.MethodGet, "/v1/billing/addons", h.ListActiveAddons},
		{http.MethodPost, "/v1/billing/addons", h.SubscribeAddon},
		{http.MethodDelete, "/v1/billing/addons/{addonId}", h.UnsubscribeAddon},
		{http.MethodGet, "/v1/billing/domains", h.Domains},
		{http.MethodPost, "/v1/billing/deposits", h.CreateDeposit},
		{http.MethodGet, "/v1/billing/deposits/{transactionId}", h.DepositStatus},
		{http.MethodDelete, "/v1/billing/deposits/{transactionId}", h.CancelDeposit},
		{http.MethodPost, "/v1/billing/payments", h.CreatePayment},
		{http.MethodPost, "/v1/billing/subscriptions", h.CreateSubscription},
		{http.MethodDelete, "/v1/billing/subscriptions", h.CancelSubscription},
		{http.MethodPost, "/v1/billing/addon-charges/pay", h.PayAddonCharges},
		{http.MethodPost, "/v1/billing/discount-codes/validate", h.ValidateDiscount},
	}
	for _, route := range routes {
		mux.HandleFunc(route.method+" "+route.path, route.fn)
		mux.HandleFunc(route.method+" "+route.path+"/", route.fn)
	}
}
