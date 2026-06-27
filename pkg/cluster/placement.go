package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

// PickPlacementDomain chooses the active cluster with the most free capacity (D30).
// Routing-only rows (no PocketBase URL in secret) are skipped.
func PickPlacementDomain(ctx context.Context, pr *postgrest.Client) (string, error) {
	if pr == nil {
		return "", fmt.Errorf("postgrest client required")
	}
	var rows []struct {
		Domain string          `json:"domain"`
		Secret json.RawMessage `json:"secret"`
	}
	q := url.Values{}
	q.Set("select", "domain,free,secret")
	q.Set("active", "eq.true")
	q.Set("order", "free.desc.nullslast")
	if err := pr.SelectService(ctx, "clusters", q, &rows); err != nil {
		return "", err
	}
	for _, row := range rows {
		sec, err := ParseSecret(row.Secret)
		if err != nil || sec.URL == "" {
			continue
		}
		domain := strings.TrimSpace(row.Domain)
		if domain != "" {
			return domain, nil
		}
	}
	return "", fmt.Errorf("no placement cluster available")
}
