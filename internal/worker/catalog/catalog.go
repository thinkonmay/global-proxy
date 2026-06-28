// Package catalog consumes catalog store enrichment jobs from the bus.
package catalog

import (
	"context"
	"fmt"
	"net/http"
	"time"

	catalogpkg "github.com/thinkonmay/global-proxy/api/pkg/catalog"
	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	"github.com/thinkonmay/global-proxy/api/pkg/idempotency"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/pkg/storeindex"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

type Handler struct {
	idem   *idempotency.Guard
	pr     *postgrest.Client
	steam  *http.Client
	stores *storeindex.Client
}

func New(idem *idempotency.Guard, pr *postgrest.Client, steamHTTP *http.Client, stores *storeindex.Client) *Handler {
	if steamHTTP == nil {
		steamHTTP = &http.Client{Timeout: 60 * time.Second}
	}
	return &Handler{
		idem:   idem,
		pr:     pr,
		steam:  steamHTTP,
		stores: stores,
	}
}

func (h *Handler) Init(eventBus bus.Client) {
	bus.Subscribe(
		eventBus,
		model.TopicCatalogStoreJob,
		"worker-catalog-store",
		h.handle,
		bus.WithConcurrency(4),
		bus.WithMaxDeliver(5),
	)
}

func (h *Handler) handle(ctx context.Context, p model.CatalogStoreJobMsg) error {
	if p.AppID <= 0 {
		return fmt.Errorf("catalog store job missing app_id")
	}
	key := p.RequestID
	if key == "" {
		key = fmt.Sprintf("catalog-store-%d", p.AppID)
	}
	return h.idem.Run(ctx, key, func(ctx context.Context) error {
		return catalogpkg.EnsureSteamStore(ctx, h.pr, h.steam, h.stores, p.AppID)
	})
}
