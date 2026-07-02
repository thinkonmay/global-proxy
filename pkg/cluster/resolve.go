package cluster

import (
	"context"
	"fmt"
	"strings"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

// ResolveGrantDomain picks the cluster domain for addon grants and user file buckets (D30).
// When volumeID is set, uses that volume's cluster; otherwise falls back to the user's
// sole cluster. Machines no longer carry a cluster (provisioning jobs are emitted
// cluster-less and resolved from the user's volume), so there is no subscription-cluster
// step here.
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
