package cluster

import (
	"context"
	"fmt"
	"net/url"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

// Info holds cluster routing data for node PocketBase calls.
type Info struct {
	ID     int64
	Domain string
}

// Lookup loads cluster domain and PocketBase base URL via PostgREST.
func Lookup(ctx context.Context, pr *postgrest.Client, clusterID int64) (Info, error) {
	var rows []struct {
		ID     int64  `json:"id"`
		Domain string `json:"domain"`
	}
	q := url.Values{}
	q.Set("select", "id,domain")
	q.Set("id", fmt.Sprintf("eq.%d", clusterID))
	q.Set("limit", "1")
	if err := pr.SelectService(ctx, "clusters", q, &rows); err != nil {
		return Info{}, err
	}
	if len(rows) == 0 {
		return Info{}, fmt.Errorf("cluster %d not found", clusterID)
	}
	row := rows[0]
	return Info{ID: row.ID, Domain: row.Domain}, nil
}
