package cluster

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

// ClusterForVolume returns the cluster id that owns volumeID for email.
func ClusterForVolume(ctx context.Context, pr *postgrest.Client, email, volumeID string) (int64, error) {
	email = strings.TrimSpace(email)
	volumeID = strings.TrimSpace(volumeID)
	if email == "" || volumeID == "" {
		return 0, fmt.Errorf("email and volume_id required")
	}
	var rows []struct {
		ClusterID *int64 `json:"cluster_id"`
	}
	q := url.Values{}
	q.Set("select", "cluster_id")
	q.Set("email", "eq."+email)
	q.Set("volume_id", "eq."+volumeID)
	q.Set("limit", "1")
	if err := pr.SelectService(ctx, "user_v2", q, &rows); err != nil {
		return 0, err
	}
	if len(rows) == 0 || rows[0].ClusterID == nil || *rows[0].ClusterID <= 0 {
		return 0, fmt.Errorf("volume not found for user")
	}
	return *rows[0].ClusterID, nil
}

// PrimaryCluster returns a single cluster id for email when exactly one cluster holds volumes.
// When the user spans multiple clusters, volumeID must be supplied via ClusterForVolume.
func PrimaryCluster(ctx context.Context, pr *postgrest.Client, email string) (int64, error) {
	groups, err := UserVolumeGroups(ctx, pr, email)
	if err != nil {
		return 0, err
	}
	if len(groups) == 0 {
		return 0, fmt.Errorf("no volumes for user")
	}
	if len(groups) > 1 {
		return 0, fmt.Errorf("multiple clusters; specify volume")
	}
	for id := range groups {
		return id, nil
	}
	return 0, fmt.Errorf("no cluster")
}
