package catalog

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/pkg/storeindex"
)

// StoreRecord is the merged catalog view used by AI search and persona enrichment.
type StoreRecord struct {
	ID               int64    `json:"id"`
	Name             string   `json:"name"`
	CodeName         string   `json:"code_name"`
	ShortDescription string   `json:"short_description"`
	HeaderImage      string   `json:"header_image"`
	Genres           []string `json:"genres"`
	Type             string   `json:"type"`
	Rank             float64  `json:"rank"`
}

// EnsureSteamStore fetches Steam appdetails, writes a slim Postgres row, and indexes
// full metadata in Elasticsearch.
func EnsureSteamStore(ctx context.Context, pr *postgrest.Client, steamHTTP *http.Client, index *storeindex.Client, appID int64) error {
	if appID <= 0 || pr == nil {
		return nil
	}

	exists, enriched, err := storeEnrichmentState(ctx, pr, index, appID)
	if err != nil {
		return err
	}
	if enriched {
		return nil
	}

	details, fetchErr := FetchSteamAppDetails(ctx, steamHTTP, appID)
	row := storeRowFromSteam(appID, details)

	q := url.Values{}
	q.Set("id", "eq."+strconv.FormatInt(appID, 10))

	if exists {
		if err := pr.Update(ctx, "stores", q, row, nil); err != nil {
			return err
		}
	} else if err := pr.Insert(ctx, "stores", row, nil); err != nil {
		if postgrest.IsConflict(err) {
			if err := pr.Update(ctx, "stores", q, row, nil); err != nil {
				return err
			}
		} else {
			return err
		}
	}

	if fetchErr == nil && details != nil && index != nil && index.Enabled() {
		genres := GenreDescriptions(details.Raw)
		doc := storeindex.DocumentFromSteam(appID, details.Name, genres, details.Raw)
		if err := index.Index(ctx, doc); err != nil {
			return err
		}
	}
	return nil
}

// LookupStore loads a store for display/search enrichment (ES first, Postgres fallback).
func LookupStore(ctx context.Context, pr *postgrest.Client, index *storeindex.Client, appID int64) (*StoreRecord, error) {
	if appID <= 0 {
		return nil, nil
	}
	if index != nil && index.Enabled() {
		doc, err := index.Get(ctx, appID)
		if err != nil {
			return nil, err
		}
		if doc != nil && doc.HeaderImage != "" {
			return &StoreRecord{
				ID:               doc.ID,
				Name:             doc.Name,
				CodeName:         doc.CodeName,
				ShortDescription: doc.ShortDescription,
				HeaderImage:      doc.HeaderImage,
				Genres:           doc.Genres,
				Type:             doc.Type,
				Rank:             2.0,
			}, nil
		}
	}
	return lookupStoreFromPostgres(ctx, pr, appID)
}

func lookupStoreFromPostgres(ctx context.Context, pr *postgrest.Client, appID int64) (*StoreRecord, error) {
	var rows []struct {
		ID               int64    `json:"id"`
		Name             string   `json:"name"`
		CodeName         string   `json:"code_name"`
		ShortDescription string   `json:"short_description"`
		HeaderImage      string   `json:"header_image"`
		Genres           []string `json:"genres"`
		Type             string   `json:"type"`
	}
	q := url.Values{}
	q.Set("select", "id,name,code_name,short_description,header_image,genres,type")
	q.Set("id", "eq."+strconv.FormatInt(appID, 10))
	q.Set("header_image", "not.is.null")
	q.Set("limit", "1")
	if err := pr.SelectService(ctx, "stores", q, &rows); err != nil {
		return nil, err
	}
	if len(rows) == 0 || rows[0].HeaderImage == "" {
		return nil, nil
	}
	row := rows[0]
	return &StoreRecord{
		ID:               row.ID,
		Name:             row.Name,
		CodeName:         row.CodeName,
		ShortDescription: row.ShortDescription,
		HeaderImage:      row.HeaderImage,
		Genres:           row.Genres,
		Type:             row.Type,
		Rank:             2.0,
	}, nil
}

func storeEnrichmentState(ctx context.Context, pr *postgrest.Client, index *storeindex.Client, appID int64) (exists, enriched bool, err error) {
	if index != nil && index.Enabled() {
		doc, err := index.Get(ctx, appID)
		if err != nil {
			return false, false, err
		}
		if doc != nil && doc.HeaderImage != "" {
			return true, true, nil
		}
	}

	var rows []struct {
		ID          int64  `json:"id"`
		HeaderImage string `json:"header_image"`
	}
	q := url.Values{}
	q.Set("select", "id,header_image")
	q.Set("id", "eq."+strconv.FormatInt(appID, 10))
	q.Set("limit", "1")
	if err := pr.SelectService(ctx, "stores", q, &rows); err != nil {
		return false, false, err
	}
	if len(rows) == 0 {
		return false, false, nil
	}
	return true, strings.TrimSpace(rows[0].HeaderImage) != "", nil
}
