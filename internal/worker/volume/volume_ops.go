package volume

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/thinkonmay/global-proxy/api/shared/model"
)

func (h *Handler) createVolume(ctx context.Context, p model.VolumeJobMsg) error {
	if err := h.provisionGlobalVolume(ctx, p); err != nil {
		_ = h.patchJob(ctx, p.JobID, false, jobErrorResult(err.Error()))
		return err
	}
	if err := h.daemonAllocate(ctx, p); err != nil {
		_ = h.patchJob(ctx, p.JobID, false, jobErrorResult(err.Error()))
		return err
	}
	return h.patchJob(ctx, p.JobID, true, jobExistsResult(p.VolumeID))
}

func (h *Handler) updateVolume(ctx context.Context, p model.VolumeJobMsg) error {
	merged, err := h.mergeVolumeConfiguration(ctx, p)
	if err != nil {
		_ = h.patchJob(ctx, p.JobID, false, jobErrorResult(err.Error()))
		return err
	}
	p.Configuration = merged
	if err := h.provisionGlobalVolume(ctx, p); err != nil {
		_ = h.patchJob(ctx, p.JobID, false, jobErrorResult(err.Error()))
		return err
	}
	return h.patchJob(ctx, p.JobID, true, []byte(`{"updated":true}`))
}

func (h *Handler) deleteVolume(ctx context.Context, p model.VolumeJobMsg) error {
	if err := h.daemonDeallocate(ctx, p); err != nil {
		_ = h.patchJob(ctx, p.JobID, false, jobErrorResult(err.Error()))
		return err
	}
	if err := h.deprovisionGlobalVolume(ctx, p); err != nil {
		_ = h.patchJob(ctx, p.JobID, false, jobErrorResult(err.Error()))
		return err
	}
	return h.patchJob(ctx, p.JobID, true, []byte(`{"deleted":true}`))
}

func (h *Handler) mergeVolumeConfiguration(ctx context.Context, p model.VolumeJobMsg) (json.RawMessage, error) {
	if p.Email == "" || p.VolumeID == "" {
		return nil, fmt.Errorf("email and volume_id required for update")
	}

	var existing json.RawMessage
	if err := h.pr.RPC(ctx, "lookup_volume_configuration_v1", map[string]any{
		"email":     p.Email,
		"volume_id": p.VolumeID,
	}, &existing); err != nil {
		return nil, err
	}

	argCfg := map[string]any{}
	if len(p.Configuration) > 0 {
		_ = json.Unmarshal(p.Configuration, &argCfg)
	}
	oldCfg := map[string]any{}
	if len(existing) > 0 && string(existing) != "null" {
		_ = json.Unmarshal(existing, &oldCfg)
	}
	for _, key := range []string{"email", "template", "disk"} {
		if v, ok := oldCfg[key]; ok {
			argCfg[key] = v
		}
	}
	return json.Marshal(argCfg)
}
