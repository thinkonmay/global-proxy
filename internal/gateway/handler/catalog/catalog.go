package catalog

import (
	"net/http"
	"time"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/pkg/router"
	"github.com/thinkonmay/global-proxy/api/pkg/storeindex"
)

const catalogQueryTimeout = 5 * time.Second

// Handler serves public /v1/catalog/* reads (D20 / P1-G).
type Handler struct {
	pr     *postgrest.Client
	stores *storeindex.Client
}

func New(pr *postgrest.Client, stores *storeindex.Client) *Handler {
	return &Handler{pr: pr, stores: stores}
}

func (h *Handler) Register(mux *http.ServeMux) {
	v1 := router.V1(mux)
	v1.GET("/catalog/plans", h.ListPlans)
	v1.GET("/catalog/plans/{planName}", h.GetPlan)
	v1.GET("/catalog/stores", h.ListStores)
	v1.GET("/catalog/stores/{storeID}/depot-keys", h.GetStoreDepotKeys)
	v1.GET("/catalog/stores/{storeID}", h.GetStore)
	v1.GET("/catalog/banners", h.ListBanners)
	v1.GET("/catalog/discounts", h.ListDiscounts)
	v1.GET("/catalog/currency-rates", h.ListCurrencyRates)
	v1.GET("/catalog/app-info/{appID}", h.AppInfo)
	v1.GET("/catalog/genres", h.ListGenres)
	v1.GET("/catalog/addons", h.ListAddons)
	v1.GET("/catalog/blog", h.ListBlog)
	v1.GET("/catalog/constants", h.ListConstants)
	v1.GET("/catalog/resources", h.ListResources)
	v1.GET("/catalog/binary-releases", h.ListBinaryReleases)
	v1.GET("/catalog/promo-banners", h.ListPromoBanners)
	v1.GET("/search/stores", h.SearchStores)
	v1.POST("/search/stores", h.SearchStoresBatch)
}
