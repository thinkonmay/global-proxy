package volume

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/thinkonmay/global-proxy/api/pkg/cluster"
	"github.com/thinkonmay/global-proxy/api/pkg/grants"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

func (h *Handler) handleGrantJob(ctx context.Context, p model.VolumeJobMsg) error {
	clusterInfo, err := cluster.Lookup(ctx, h.pr, p.ClusterID)
	if err != nil {
		return h.patchJob(ctx, p.JobID, false, jobErrorResult(err.Error()))
	}
	domain := strings.TrimSpace(clusterInfo.Domain)
	if domain == "" {
		return h.patchJob(ctx, p.JobID, false, jobErrorResult("cluster domain missing"))
	}

	args := map[string]any{"email": p.Email, "domain": domain}
	var result any
	switch p.Command {
	case "grant buckets":
		cred, err := grants.GrantBucketAccess(ctx, h.pr, h.storj, p.Email, domain)
		if err != nil {
			if patchErr := h.patchJob(ctx, p.JobID, false, jobErrorResult(err.Error())); patchErr != nil {
				return patchErr
			}
			return nil
		}
		result = cred
	default:
		rpcName := rpcForGrantCommand(p.Command, p.Configuration, args)
		if rpcName == "" {
			return fmt.Errorf("unsupported grant command %q", p.Command)
		}
		if err := h.pr.RPC(ctx, rpcName, args, &result); err != nil {
			if patchErr := h.patchJob(ctx, p.JobID, false, jobErrorResult(err.Error())); patchErr != nil {
				return patchErr
			}
			return nil
		}
	}

	respBody, _ := json.Marshal(result)
	if len(respBody) == 0 || string(respBody) == "null" {
		respBody = []byte(`{"ok":true}`)
	}
	return h.patchJob(ctx, p.JobID, true, respBody)
}

func rpcForGrantCommand(command string, configuration json.RawMessage, args map[string]any) string {
	switch command {
	case "grant app_access":
		if appID := configString(configuration, "app_id"); appID != "" {
			args["app_id"] = appID
		}
		return "grant_app_access_v1"
	case "grant llm":
		return "grant_llm_access_v1"
	case "unmap buckets":
		return "unmap_bucket_access_v1"
	case "unmap app_access":
		return "unmap_app_access_v1"
	case "unmap llm":
		return "unmap_llm_access_v1"
	case "reset app_access":
		return "reset_user_app_access_usage_v1"
	case "reset llm":
		return "reset_user_llm_usage_v1"
	default:
		return ""
	}
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
