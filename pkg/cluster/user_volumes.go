package cluster

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

// UserVolumeRow ties a user's volume to a cluster via public.user_v2 (join view over infra.volumes).
type UserVolumeRow struct {
	ClusterID int64
	VolumeID  string
}

// UserVolumeGroups returns distinct clusters and volume ids owned by email.
func UserVolumeGroups(ctx context.Context, pr *postgrest.Client, email string) (map[int64][]string, error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return nil, fmt.Errorf("email required")
	}
	var rows []struct {
		ClusterID *int64 `json:"cluster_id"`
		VolumeID  string `json:"volume_id"`
	}
	q := url.Values{}
	q.Set("select", "cluster_id,volume_id")
	q.Set("email", "eq."+email)
	if err := pr.SelectService(ctx, "user_v2", q, &rows); err != nil {
		return nil, err
	}
	out := map[int64][]string{}
	for _, row := range rows {
		if row.ClusterID == nil || *row.ClusterID <= 0 {
			continue
		}
		vol := strings.TrimSpace(row.VolumeID)
		if vol == "" {
			continue
		}
		cid := *row.ClusterID
		out[cid] = append(out[cid], vol)
	}
	return out, nil
}

// GrpcTarget returns host:port for cluster-master virtdaemon gRPC.
func GrpcTarget(info Info, port int, homeIssuerHost, homeOverride string) string {
	if o := strings.TrimSpace(homeOverride); o != "" {
		if homeIssuerHost == "" || strings.EqualFold(NormalizeHost(info.Domain), NormalizeHost(homeIssuerHost)) {
			return o
		}
	}
	if port <= 0 {
		port = 50000
	}
	host := NormalizeHost(info.Domain)
	if host == "" {
		return ""
	}
	return host + ":" + strconv.Itoa(port)
}
