package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/thinkonmay/global-proxy/api/pkg/cluster"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

func (h *volumeHandler) handleGrantJob(ctx context.Context, p model.VolumeJobPayload) error {
	clusterInfo, err := cluster.Lookup(ctx, h.pr, p.ClusterID)
	if err != nil {
		return h.patchJob(ctx, p.JobID, false, jobErrorResult(err.Error()))
	}
	domain := strings.TrimSpace(clusterInfo.Domain)
	if domain == "" {
		return h.patchJob(ctx, p.JobID, false, jobErrorResult("cluster domain missing"))
	}

	args := map[string]any{"email": p.Email, "domain": domain}
	var rpcName string
	switch p.Command {
	case "grant buckets":
		rpcName = "grant_bucket_access_v1"
	case "grant app_access":
		rpcName = "grant_app_access_v1"
		if appID := configString(p.Configuration, "app_id"); appID != "" {
			args["app_id"] = appID
		}
	case "grant llm":
		rpcName = "grant_llm_access_v1"
	case "unmap buckets":
		rpcName = "unmap_bucket_access_v1"
	case "unmap app_access":
		rpcName = "unmap_app_access_v1"
	case "unmap llm":
		rpcName = "unmap_llm_access_v1"
	case "reset app_access":
		rpcName = "reset_user_app_access_usage_v1"
	case "reset llm":
		rpcName = "reset_user_llm_usage_v1"
	default:
		return fmt.Errorf("unsupported grant command %q", p.Command)
	}

	var result any
	if err := h.pr.RPC(ctx, rpcName, args, &result); err != nil {
		return h.patchJob(ctx, p.JobID, false, jobErrorResult(err.Error()))
	}

	respBody, _ := json.Marshal(result)
	if len(respBody) == 0 || string(respBody) == "null" {
		respBody = []byte(`{"ok":true}`)
	}
	return h.patchJob(ctx, p.JobID, true, respBody)
}

func configString(raw json.RawMessage, key string) string {
	if len(raw) == 0 {
		return ""
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return ""
	}
	v, _ := m[key].(string)
	return strings.TrimSpace(v)
}
