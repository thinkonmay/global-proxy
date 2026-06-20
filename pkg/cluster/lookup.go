package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

// Info holds cluster routing data for node PocketBase calls.
type Info struct {
	ID     int64
	Domain string
	URL    string
}

// Lookup loads cluster domain and PocketBase base URL via PostgREST.
func Lookup(ctx context.Context, pr *postgrest.Client, clusterID int64) (Info, error) {
	var rows []struct {
		ID     int64           `json:"id"`
		Domain string          `json:"domain"`
		Secret json.RawMessage `json:"secret"`
	}
	q := url.Values{}
	q.Set("select", "id,domain,secret")
	q.Set("id", fmt.Sprintf("eq.%d", clusterID))
	q.Set("limit", "1")
	if err := pr.SelectService(ctx, "clusters", q, &rows); err != nil {
		return Info{}, err
	}
	if len(rows) == 0 {
		return Info{}, fmt.Errorf("cluster %d not found", clusterID)
	}
	row := rows[0]
	baseURL := ""
	if sec, err := ParseSecret(row.Secret); err == nil {
		baseURL = sec.URL
	}
	if baseURL == "" && row.Domain != "" {
		baseURL = "https://" + row.Domain
	}
	if baseURL == "" {
		return Info{}, fmt.Errorf("cluster %d missing url", clusterID)
	}
	return Info{ID: row.ID, Domain: row.Domain, URL: baseURL}, nil
}
