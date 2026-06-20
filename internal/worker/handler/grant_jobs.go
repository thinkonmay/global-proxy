package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/thinkonmay/global-proxy/api/pkg/cluster"
	"github.com/thinkonmay/global-proxy/api/pkg/pocketbase"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

const defaultLLMModel = "gemini-3-flash-preview"

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

	// Cluster PocketBase side effects (G8): worker owns node API calls, not Postgres HTTP.
	if err := h.runGrantClusterSideEffects(ctx, p, clusterInfo); err != nil {
		var pe *pocketbase.Error
		if errors.As(err, &pe) {
			return h.patchJob(ctx, p.JobID, false, pe.Body)
		}
		return h.patchJob(ctx, p.JobID, false, jobErrorResult(err.Error()))
	}

	respBody, _ := json.Marshal(result)
	if len(respBody) == 0 || string(respBody) == "null" {
		respBody = []byte(`{"ok":true}`)
	}
	return h.patchJob(ctx, p.JobID, true, respBody)
}

func (h *volumeHandler) runGrantClusterSideEffects(ctx context.Context, p model.VolumeJobPayload, clusterInfo cluster.Info) error {
	switch p.Command {
	case "grant app_access", "grant buckets", "grant llm":
		pb := h.pb.WithBaseURL(clusterInfo.URL)
		userID, err := h.ensurePBUser(ctx, pb, p.Email)
		if err != nil {
			return err
		}
		if p.Command == "grant llm" {
			return h.ensurePBLLMModel(ctx, pb, userID)
		}
		return nil
	case "unmap llm":
		pb := h.pb.WithBaseURL(clusterInfo.URL)
		userID, err := h.ensurePBUser(ctx, pb, p.Email)
		if err != nil {
			return err
		}
		return h.deletePBLLMModel(ctx, pb, userID)
	case "reset app_access":
		return h.resetPBAppAccessUsage(ctx, clusterInfo.URL, p.Email)
	case "reset llm":
		return h.resetPBLLMUsage(ctx, clusterInfo.URL, p.Email)
	default:
		return nil
	}
}

func (h *volumeHandler) ensurePBLLMModel(ctx context.Context, pb *pocketbase.Client, userID string) error {
	q := url.Values{}
	q.Set("filter", `(user~"`+userID+`")`)
	var list struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	if err := pb.ListRecords(ctx, "llmModels", q, &list); err != nil {
		return err
	}
	if len(list.Items) > 0 {
		return nil
	}
	var created map[string]any
	return pb.CreateRecord(ctx, "llmModels", map[string]any{
		"user":  userID,
		"model": defaultLLMModel,
		"usage": 0,
	}, &created)
}

func (h *volumeHandler) deletePBLLMModel(ctx context.Context, pb *pocketbase.Client, userID string) error {
	q := url.Values{}
	q.Set("filter", `(user~"`+userID+`")`)
	var list struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	if err := pb.ListRecords(ctx, "llmModels", q, &list); err != nil {
		return err
	}
	if len(list.Items) == 0 {
		return nil
	}
	return pb.DeleteRecord(ctx, "llmModels", list.Items[0].ID)
}

func (h *volumeHandler) resetPBAppAccessUsage(ctx context.Context, baseURL, email string) error {
	pb := h.pb.WithBaseURL(baseURL)
	userID, err := h.ensurePBUser(ctx, pb, email)
	if err != nil {
		return err
	}
	return h.patchPBUsage(ctx, pb, "app_access", userID, 0)
}

func (h *volumeHandler) resetPBLLMUsage(ctx context.Context, baseURL, email string) error {
	pb := h.pb.WithBaseURL(baseURL)
	userID, err := h.ensurePBUser(ctx, pb, email)
	if err != nil {
		return err
	}
	return h.patchPBUsage(ctx, pb, "llmModels", userID, 0)
}

func (h *volumeHandler) patchPBUsage(ctx context.Context, pb *pocketbase.Client, collection, userID string, usage int) error {
	q := url.Values{}
	q.Set("filter", `(user~"`+userID+`")`)
	var list struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	if err := pb.ListRecords(ctx, collection, q, &list); err != nil {
		return err
	}
	if len(list.Items) == 0 {
		return nil
	}
	var updated map[string]any
	return pb.UpdateRecord(ctx, collection, list.Items[0].ID, map[string]any{"usage": usage}, &updated)
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
