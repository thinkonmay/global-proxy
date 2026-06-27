package cluster

import (
	"context"
	"fmt"
	"strings"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

// ResolveGrantDomain picks the cluster domain for addon grants and user file buckets (D30).
// When volumeID is set, uses that volume's cluster; otherwise prefers the active
// subscription cluster, then the user's sole cluster.
func ResolveGrantDomain(ctx context.Context, pr *postgrest.Client, email, volumeID string) (string, error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return "", fmt.Errorf("email required")
	}
	if vol := strings.TrimSpace(volumeID); vol != "" {
		cid, err := ClusterForVolume(ctx, pr, email, vol)
		if err != nil {
			return "", err
		}
		return domainForClusterID(ctx, pr, cid)
	}
	if domain, err := subscriptionClusterDomain(ctx, pr, email); err == nil && domain != "" {
		return domain, nil
	}
	cid, err := PrimaryCluster(ctx, pr, email)
	if err != nil {
		return "", err
	}
	return domainForClusterID(ctx, pr, cid)
}

func domainForClusterID(ctx context.Context, pr *postgrest.Client, id int64) (string, error) {
	info, err := Lookup(ctx, pr, id)
	if err != nil {
		return "", err
	}
	domain := NormalizeHost(info.Domain)
	if domain == "" {
		return "", fmt.Errorf("cluster domain missing")
	}
	return domain, nil
}

func subscriptionClusterDomain(ctx context.Context, pr *postgrest.Client, email string) (string, error) {
	var rows []struct {
		Cluster string `json:"cluster"`
	}
	if err := pr.RPC(ctx, "get_subscription_v3", map[string]any{"email": email}, &rows); err != nil {
		return "", err
	}
	if len(rows) == 0 {
		return "", fmt.Errorf("no subscription")
	}
	domain := NormalizeHost(rows[0].Cluster)
	if domain == "" {
		return "", fmt.Errorf("subscription cluster empty")
	}
	return domain, nil
}
