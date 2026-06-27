package cluster

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

// Register upserts infra.clusters (and optional infra.nodes) via register_cluster_v1.
func Register(ctx context.Context, pr *postgrest.Client, domain, node string, free *int) error {
	domain = NormalizeHost(domain)
	if domain == "" {
		return nil
	}
	node = strings.TrimSpace(node)
	args := map[string]any{
		"p_domain": domain,
	}
	if node != "" {
		args["p_node"] = node
	}
	if free != nil {
		args["p_free"] = *free
	}
	return pr.RPC(ctx, "register_cluster_v1", args, nil)
}

// FreeGBFromWorkerInfoJSON estimates placement free space (GB) from a WorkerInfor JSON body.
func FreeGBFromWorkerInfoJSON(body []byte) (int, bool) {
	if len(body) == 0 {
		return 0, false
	}
	var info struct {
		Pools []struct {
			Size  int64 `json:"size"`
			Used  int64 `json:"used"`
			Total int64 `json:"total"`
		} `json:"Pools"`
	}
	if err := json.Unmarshal(body, &info); err != nil || len(info.Pools) == 0 {
		return 0, false
	}
	var freeBytes int64
	for _, p := range info.Pools {
		capacity := p.Total
		if capacity <= 0 {
			capacity = p.Size
		}
		if capacity <= 0 {
			continue
		}
		avail := capacity - p.Used
		if avail > 0 {
			freeBytes += avail
		}
	}
	if freeBytes <= 0 {
		return 0, false
	}
	gb := int(freeBytes / (1024 * 1024 * 1024))
	if gb <= 0 {
		gb = 1
	}
	return gb, true
}
