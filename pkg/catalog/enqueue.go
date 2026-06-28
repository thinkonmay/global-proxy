package catalog

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/pkg/storeindex"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

// StoreDeps configures catalog resolve/enqueue helpers.
type StoreDeps struct {
	PostgREST  *postgrest.Client
	SteamHTTP  *http.Client
	StoreIndex *storeindex.Client
	Bus        bus.Client
}

// EnqueueEnsureSteamStore publishes a catalog enrichment job for the worker.
func EnqueueEnsureSteamStore(ctx context.Context, b bus.Client, appID int64) error {
	if b == nil || appID <= 0 {
		return nil
	}
	return bus.Publish(ctx, b, model.TopicCatalogStoreJob, model.CatalogStoreJobMsg{
		RequestID: fmt.Sprintf("catalog-store-%d", appID),
		AppID:     appID,
		Type:      "STEAM",
	})
}

// ResolveStore returns an enriched store, enqueueing a worker job when missing.
// Falls back to in-process EnsureSteamStore when the bus is unavailable.
func ResolveStore(ctx context.Context, deps StoreDeps, appID int64) (*StoreRecord, error) {
	if appID <= 0 {
		return nil, nil
	}
	rec, err := LookupStore(ctx, deps.PostgREST, deps.StoreIndex, appID)
	if err != nil || rec != nil {
		return rec, err
	}
	if deps.Bus != nil {
		if err := EnqueueEnsureSteamStore(ctx, deps.Bus, appID); err != nil {
			return nil, err
		}
		rec, err := waitLookup(ctx, deps, appID)
		if err != nil {
			return nil, err
		}
		if rec != nil {
			return rec, nil
		}
		// Worker did not finish in time (slow Steam fetch or worker offline).
		if err := EnsureSteamStore(ctx, deps.PostgREST, deps.SteamHTTP, deps.StoreIndex, appID); err != nil {
			return nil, err
		}
		return LookupStore(ctx, deps.PostgREST, deps.StoreIndex, appID)
	}
	if err := EnsureSteamStore(ctx, deps.PostgREST, deps.SteamHTTP, deps.StoreIndex, appID); err != nil {
		return nil, err
	}
	return LookupStore(ctx, deps.PostgREST, deps.StoreIndex, appID)
}

func waitLookup(ctx context.Context, deps StoreDeps, appID int64) (*StoreRecord, error) {
	const attempts = 10
	const delay = 150 * time.Millisecond
	for i := 0; i < attempts; i++ {
		rec, err := LookupStore(ctx, deps.PostgREST, deps.StoreIndex, appID)
		if err != nil || rec != nil {
			return rec, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delay):
		}
	}
	return nil, nil
}
