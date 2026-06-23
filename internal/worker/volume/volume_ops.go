package volume

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/thinkonmay/global-proxy/api/pkg/pocketbase"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

func (h *Handler) createVolume(ctx context.Context, p model.VolumeJobMsg) error {
	baseURL, err := h.clusterURL(ctx, p.ClusterID)
	if err != nil {
		return h.patchJob(ctx, p.JobID, false, jobErrorResult(err.Error()))
	}
	pb := h.pb.WithBaseURL(baseURL)
	userID, err := h.ensurePBUser(ctx, pb, p.Email)
	if err != nil {
		if isPermanentDispatchError(err) {
			return h.patchJob(ctx, p.JobID, false, jobErrorResult(err.Error()))
		}
		return err
	}

	body := map[string]any{
		"user":     userID,
		"local_id": p.VolumeID,
	}
	if len(p.Configuration) > 0 {
		var cfg map[string]any
		if json.Unmarshal(p.Configuration, &cfg) == nil {
			for k, v := range cfg {
				body[k] = v
			}
		}
	}

	headers := http.Header{}
	headers.Set("Idempotency-Key", fmt.Sprintf("%d", p.JobID))
	var created map[string]any
	err = pb.CreateRecord(ctx, "volumes", body, &created, pocketbase.WithHeaders(headers))
	if err != nil {
		if p.VolumeID != "" && h.volumeExistsByLocalID(ctx, pb, userID, p.VolumeID) {
			return h.patchJob(ctx, p.JobID, true, jobExistsResult(p.VolumeID))
		}
		return h.patchJobFromPBError(ctx, p.JobID, err)
	}
	respBody, _ := json.Marshal(created)
	return h.patchJob(ctx, p.JobID, true, respBody)
}

func (h *Handler) volumeExistsByLocalID(ctx context.Context, pb *pocketbase.Client, userID, localID string) bool {
	if localID == "" {
		return false
	}
	q := url.Values{}
	q.Set("filter", fmt.Sprintf(`(user~"%s" && local_id="%s")`, userID, localID))
	var list struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	if err := pb.ListRecords(ctx, "volumes", q, &list); err != nil {
		return false
	}
	return len(list.Items) > 0
}

func (h *Handler) updateVolume(ctx context.Context, p model.VolumeJobMsg) error {
	baseURL, err := h.clusterURL(ctx, p.ClusterID)
	if err != nil {
		return h.patchJob(ctx, p.JobID, false, jobErrorResult(err.Error()))
	}
	pb := h.pb.WithBaseURL(baseURL)
	userID, err := h.ensurePBUser(ctx, pb, p.Email)
	if err != nil {
		if isPermanentDispatchError(err) {
			return h.patchJob(ctx, p.JobID, false, jobErrorResult(err.Error()))
		}
		return err
	}

	q := url.Values{}
	q.Set("filter", `(user~"`+userID+`")`)
	var list struct {
		Items []struct {
			ID            string          `json:"id"`
			Configuration json.RawMessage `json:"configuration"`
		} `json:"items"`
	}
	if err := pb.ListRecords(ctx, "volumes", q, &list); err != nil {
		if isPermanentDispatchError(err) {
			return h.patchJob(ctx, p.JobID, false, jobErrorResult(err.Error()))
		}
		return err
	}
	if len(list.Items) == 0 {
		return h.patchJob(ctx, p.JobID, false, jobErrorResult("Volume not found"))
	}

	item := list.Items[0]
	argCfg := map[string]any{}
	if len(p.Configuration) > 0 {
		_ = json.Unmarshal(p.Configuration, &argCfg)
	}
	var oldCfg map[string]any
	if len(item.Configuration) > 0 {
		_ = json.Unmarshal(item.Configuration, &oldCfg)
	}
	for _, key := range []string{"email", "template", "disk"} {
		if oldCfg != nil {
			if v, ok := oldCfg[key]; ok {
				argCfg[key] = v
			}
		}
	}

	headers := http.Header{}
	headers.Set("Idempotency-Key", fmt.Sprintf("%d", p.JobID))
	var updated map[string]any
	err = pb.UpdateRecord(ctx, "volumes", item.ID, map[string]any{"configuration": argCfg}, &updated, pocketbase.WithHeaders(headers))
	if err != nil {
		return h.patchJobFromPBError(ctx, p.JobID, err)
	}
	respBody, _ := json.Marshal(updated)
	return h.patchJob(ctx, p.JobID, true, respBody)
}

func (h *Handler) deleteVolume(ctx context.Context, p model.VolumeJobMsg) error {
	baseURL, err := h.clusterURL(ctx, p.ClusterID)
	if err != nil {
		return h.patchJob(ctx, p.JobID, false, jobErrorResult(err.Error()))
	}
	pb := h.pb.WithBaseURL(baseURL)
	userID, err := h.ensurePBUser(ctx, pb, p.Email)
	if err != nil {
		if isPermanentDispatchError(err) {
			return h.patchJob(ctx, p.JobID, false, jobErrorResult(err.Error()))
		}
		return err
	}

	q := url.Values{}
	q.Set("filter", `(user~"`+userID+`")`)
	var list struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	if err := pb.ListRecords(ctx, "volumes", q, &list); err != nil {
		if isPermanentDispatchError(err) {
			return h.patchJob(ctx, p.JobID, false, jobErrorResult(err.Error()))
		}
		return err
	}
	if len(list.Items) == 0 {
		return h.patchJob(ctx, p.JobID, false, jobErrorResult("Volume not found"))
	}

	headers := http.Header{}
	headers.Set("Idempotency-Key", fmt.Sprintf("%d", p.JobID))
	if err := pb.DeleteRecord(ctx, "volumes", list.Items[0].ID, pocketbase.WithHeaders(headers)); err != nil {
		if pocketbase.IsNotFound(err) {
			return h.patchJob(ctx, p.JobID, true, []byte(`{"deleted":true}`))
		}
		return h.patchJobFromPBError(ctx, p.JobID, err)
	}
	return h.patchJob(ctx, p.JobID, true, []byte(`{"deleted":true}`))
}
