package persona

import (
	"context"
	"net/http"
	"strings"

	"github.com/thinkonmay/global-proxy/api/pkg/bus"
	"github.com/thinkonmay/global-proxy/api/pkg/catalog"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/pkg/storeindex"
)

type storeEnricher struct {
	pr      *postgrest.Client
	http    *http.Client
	stores  *storeindex.Client
	bus     bus.Client
	spacing func(context.Context) error
}

func newStoreEnricher(pr *postgrest.Client, httpClient *http.Client, stores *storeindex.Client, b bus.Client, spacing func(context.Context) error) *storeEnricher {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &storeEnricher{pr: pr, http: httpClient, stores: stores, bus: b, spacing: spacing}
}

func (e *storeEnricher) enrichResult(ctx context.Context, result *Result) error {
	if result == nil || e.pr == nil {
		return nil
	}
	for i := range result.UserRecommendation {
		pref := &result.UserRecommendation[i]
		for j := range pref.Recommendations {
			rec := &pref.Recommendations[j]
			if err := e.enrichOne(ctx, rec); err != nil {
				return err
			}
		}
	}
	return nil
}

func (e *storeEnricher) enrichOne(ctx context.Context, rec *RecommendedGame) error {
	if rec == nil || strings.TrimSpace(rec.Name) == "" {
		return nil
	}
	if e.spacing != nil {
		if err := e.spacing(ctx); err != nil {
			return err
		}
	}
	id := rec.ID
	if id <= 0 {
		hits, err := searchSteamStore(ctx, e.http, rec.Name)
		if err != nil {
			return err
		}
		var ok bool
		id, ok = bestSteamMatch(hits, rec.Name)
		if !ok {
			return nil
		}
		rec.ID = id
	}
	info, err := e.lookupStore(ctx, int64(id))
	if err != nil {
		return err
	}
	if info == nil {
		record, err := catalog.ResolveStore(ctx, catalog.StoreDeps{
			PostgREST:  e.pr,
			SteamHTTP:  e.http,
			StoreIndex: e.stores,
			Bus:        e.bus,
		}, int64(id))
		if err != nil {
			return err
		}
		if record != nil {
			info = storeGameFromRecord(record)
		}
	}
	if info != nil {
		rec.Info = info
	}
	return nil
}

func (e *storeEnricher) lookupStore(ctx context.Context, id int64) (*StoreGame, error) {
	rec, err := catalog.LookupStore(ctx, e.pr, e.stores, id)
	if err != nil || rec == nil {
		return nil, err
	}
	return storeGameFromRecord(rec), nil
}

func storeGameFromRecord(rec *catalog.StoreRecord) *StoreGame {
	return &StoreGame{
		ID:               rec.ID,
		Name:             rec.Name,
		CodeName:         rec.CodeName,
		ShortDescription: rec.ShortDescription,
		HeaderImage:      rec.HeaderImage,
		Genres:           rec.Genres,
		Type:             rec.Type,
		Rank:             rec.Rank,
	}
}
