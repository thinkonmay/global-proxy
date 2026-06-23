package catalog

import (
	"net/http"
	"time"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

const catalogQueryTimeout = 5 * time.Second

// Handler serves public /v1/catalog/* reads (D20 / P1-G).
type Handler struct {
	pr *postgrest.Client
}

func New(pr *postgrest.Client) *Handler {
	return &Handler{pr: pr}
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/catalog/plans", h.ListPlans)
	mux.HandleFunc("GET /v1/catalog/plans/{planName}", h.GetPlan)
	mux.HandleFunc("GET /v1/catalog/stores", h.ListStores)
	mux.HandleFunc("GET /v1/catalog/stores/{storeID}/depot-keys", h.GetStoreDepotKeys)
	mux.HandleFunc("GET /v1/catalog/stores/{storeID}", h.GetStore)
	mux.HandleFunc("GET /v1/catalog/banners", h.ListBanners)
	mux.HandleFunc("GET /v1/catalog/discounts", h.ListDiscounts)
	mux.HandleFunc("GET /v1/catalog/currency-rates", h.ListCurrencyRates)
	mux.HandleFunc("GET /v1/catalog/app-info", h.AppInfo)
	mux.HandleFunc("GET /v1/catalog/genres", h.ListGenres)
	mux.HandleFunc("GET /v1/catalog/addons", h.ListAddons)
	mux.HandleFunc("GET /v1/catalog/blog", h.ListBlog)
	mux.HandleFunc("GET /v1/catalog/constants", h.ListConstants)
	mux.HandleFunc("GET /v1/catalog/resources", h.ListResources)
	mux.HandleFunc("GET /v1/catalog/binary-releases", h.ListBinaryReleases)
	mux.HandleFunc("GET /v1/catalog/promo-banners", h.ListPromoBanners)
	mux.HandleFunc("GET /v1/search/stores", h.SearchStores)
	mux.HandleFunc("POST /v1/search/stores", h.SearchStoresBatch)
	mux.HandleFunc("POST /v1/search/stores/", h.SearchStoresBatch)
}
