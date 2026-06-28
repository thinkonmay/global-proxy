package persona

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

type storeEnricher struct {
	pr     *postgrest.Client
	http   *http.Client
	spacing func(context.Context) error
}

func newStoreEnricher(pr *postgrest.Client, httpClient *http.Client, spacing func(context.Context) error) *storeEnricher {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &storeEnricher{pr: pr, http: httpClient, spacing: spacing}
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
		_ = e.pr.Insert(ctx, "stores", map[string]any{"id": id, "type": "STEAM"}, nil)
		info, _ = e.lookupStore(ctx, int64(id))
	}
	if info != nil {
		rec.Info = info
	}
	return nil
}

func (e *storeEnricher) lookupStore(ctx context.Context, id int64) (*StoreGame, error) {
	var rows []StoreGame
	if err := e.pr.RPC(ctx, "search_stores", map[string]any{"text": strconv.FormatInt(id, 10)}, &rows); err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return &rows[0], nil
}
