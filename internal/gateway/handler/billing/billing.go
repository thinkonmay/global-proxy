package billing

import (
	"net/http"
	"time"

	payment "github.com/thinkonmay/global-proxy/api/pkg/payment"
	registry "github.com/thinkonmay/global-proxy/api/pkg/payment/registry"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/pkg/router"
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
	v1 := router.V1(mux)
	v1.GET("/billing/wallet", h.Wallet)
	v1.GET("/billing/subscription", h.Subscription)
	v1.GET("/billing/addon-charges", h.AddonCharges)
	v1.GET("/billing/addons", h.ListActiveAddons)
	v1.POST("/billing/addons", h.SubscribeAddon)
	v1.DELETE("/billing/addons/{addonId}", h.UnsubscribeAddon)
	v1.POST("/billing/deposits", h.CreateDeposit)
	v1.GET("/billing/deposits/{transactionId}", h.DepositStatus)
	v1.DELETE("/billing/deposits/{transactionId}", h.CancelDeposit)
	v1.POST("/billing/payments", h.CreatePayment)
	v1.POST("/billing/subscriptions", h.CreateSubscription)
	v1.DELETE("/billing/subscriptions", h.CancelSubscription)
	v1.POST("/billing/addon-charges/pay", h.PayAddonCharges)
	v1.POST("/billing/discount-codes/validate", h.ValidateDiscount)
}
