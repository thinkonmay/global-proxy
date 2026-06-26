package pwa

import (
	"net/http"
	"strings"
	"time"

	"github.com/thinkonmay/global-proxy/api/config"
	personah "github.com/thinkonmay/global-proxy/api/internal/gateway/handler/persona"
	"github.com/thinkonmay/global-proxy/api/pkg/pocketbase"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/pkg/router"
)

const pwaQueryTimeout = 5 * time.Second

// Handler serves browser PWA API routes (replaces website/app/api/*).
type Handler struct {
	pr         *postgrest.Client
	pbAdmin    *pocketbase.Client
	pbURL      string
	persona    *personah.Handler
	llm        config.LLM
	httpClient *http.Client
	transport  http.RoundTripper
}

func New(cfg config.Config, pr *postgrest.Client, rt http.RoundTripper, persona *personah.Handler) *Handler {
	if rt == nil {
		rt = http.DefaultTransport
	}
	return &Handler{
		pr:      pr,
		pbURL:   strings.TrimRight(cfg.PocketBase.URL, "/"),
		pbAdmin: pocketbase.New(pocketbase.Config{URL: cfg.PocketBase.URL, Username: cfg.PocketBase.Username, Password: cfg.PocketBase.Password, Transport: rt}),
		persona: persona,
		llm:     cfg.LLM,
		httpClient: &http.Client{
			Timeout:   60 * time.Second,
			Transport: rt,
		},
		transport: rt,
	}
}

// Register mounts PWA endpoints under /api/pwa/* and legacy /api/* aliases.
func (h *Handler) Register(mux *http.ServeMux) {
	routes := []struct {
		method string
		path   string
		fn     http.HandlerFunc
	}{
		{http.MethodGet, "/app_info", h.AppInfo},
		{http.MethodGet, "/currency_rates", h.CurrencyRates},
		{http.MethodGet, "/plans", h.Plans},
		{http.MethodPost, "/feedback", h.Feedback},
		{http.MethodPost, "/referrals", h.Referrals},
		{http.MethodPost, "/is_superuser", h.IsSuperuser},
		{http.MethodPost, "/update_code_name", h.UpdateCodeName},
		{http.MethodPost, "/search", h.Search},
		{http.MethodGet, "/persona/recommendations", h.persona.GetRecommendations},
	}
	// Canonical /api/pwa/* plus legacy /api/* aliases.
	pwaGroup := router.New(mux, "/api/pwa")
	legacyGroup := router.New(mux, "/api")
	for _, route := range routes {
		pwaGroup.Handle(route.method, route.path, route.fn)
		legacyGroup.Handle(route.method, route.path, route.fn)
	}
}
