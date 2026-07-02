package pwa

import (
	"net/http"
	"time"

	"github.com/thinkonmay/global-proxy/api/config"
	personah "github.com/thinkonmay/global-proxy/api/internal/gateway/handler/persona"
	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/pkg/router"
	"github.com/thinkonmay/global-proxy/api/pkg/storeindex"
)

const pwaQueryTimeout = 5 * time.Second

// Handler serves LLM-assisted store search at POST /v1/search/ai.
type Handler struct {
	pr         *postgrest.Client
	persona    *personah.Handler
	llm        config.LLM
	serpAPIKey string
	stores     *storeindex.Client
	bus        bus.Client
	httpClient *http.Client
	transport  http.RoundTripper
}

func New(cfg config.Config, pr *postgrest.Client, rt http.RoundTripper, persona *personah.Handler, stores *storeindex.Client, eventBus bus.Client) *Handler {
	if rt == nil {
		rt = http.DefaultTransport
	}
	return &Handler{
		pr:         pr,
		persona:    persona,
		llm:        cfg.LLM,
		serpAPIKey: cfg.SerpAPI.APIKey,
		stores:     stores,
		bus:        eventBus,
		httpClient: &http.Client{
			Timeout:   60 * time.Second,
			Transport: rt,
		},
		transport: rt,
	}
}

// Register mounts POST /v1/search/ai (LLM + catalog enrich).
func (h *Handler) Register(mux *http.ServeMux) {
	router.V1(mux).POST("/search/ai", h.Search)
}
