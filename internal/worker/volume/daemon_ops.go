package volume

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/thinkonmay/global-proxy/api/pkg/cluster"
	"github.com/thinkonmay/global-proxy/api/shared/model"
)

type volumeConfiguration struct {
	Template  *string `json:"template"`
	Transient *bool   `json:"transient"`
}

func (h *Handler) provisionGlobalVolume(ctx context.Context, p model.VolumeJobMsg) error {
	if p.Email == "" || p.VolumeID == "" {
		return fmt.Errorf("email and volume_id required for provision")
	}
	info, err := cluster.Lookup(ctx, h.pr, p.ClusterID)
	if err != nil {
		return err
	}
	var cfg any
	if len(p.Configuration) > 0 {
		_ = json.Unmarshal(p.Configuration, &cfg)
	}
	if cfg == nil {
		cfg = map[string]any{}
	}
	return h.pr.RPC(ctx, "provision_volume_v1", map[string]any{
		"email":           p.Email,
		"volume_id":       p.VolumeID,
		"cluster_domain":  info.Domain,
		"configuration": cfg,
	}, nil)
}

func (h *Handler) deprovisionGlobalVolume(ctx context.Context, p model.VolumeJobMsg) error {
	if p.Email == "" || p.VolumeID == "" {
		return fmt.Errorf("email and volume_id required for deprovision")
	}
	return h.pr.RPC(ctx, "deprovision_volume_v1", map[string]any{
		"email":     p.Email,
		"volume_id": p.VolumeID,
	}, nil)
}

func volumeDaemonArgs(p model.VolumeJobMsg) (template string, transient bool) {
	template = "win11.template"
	transient = false
	if len(p.Configuration) == 0 {
		return template, transient
	}
	var conf volumeConfiguration
	if json.Unmarshal(p.Configuration, &conf) != nil {
		return template, transient
	}
	if conf.Template != nil && *conf.Template != "" {
		template = *conf.Template
	}
	if conf.Transient != nil {
		transient = *conf.Transient
	}
	return template, transient
}

func (h *Handler) daemonAllocate(ctx context.Context, p model.VolumeJobMsg) error {
	if h.dc == nil {
		return nil
	}
	template, transient := volumeDaemonArgs(p)
	return h.dc.AllocateVolume(ctx, p.ClusterID, p.VolumeID, template, transient)
}

func (h *Handler) daemonDeallocate(ctx context.Context, p model.VolumeJobMsg) error {
	if h.dc == nil || p.VolumeID == "" {
		return nil
	}
	return h.dc.DeallocateVolume(ctx, p.ClusterID, p.VolumeID)
}

func (h *Handler) snapshotAll(ctx context.Context, p model.VolumeJobMsg) error {
	if h.dc == nil {
		return h.patchJob(ctx, p.JobID, false, jobErrorResult("daemon gRPC not configured"))
	}
	var args struct {
		VolumeIDs []string `json:"volume_ids"`
	}
	if len(p.Arguments) > 0 {
		_ = json.Unmarshal(p.Arguments, &args)
	}
	if err := h.dc.SnapshotAll(ctx, p.ClusterID, args.VolumeIDs); err != nil {
		return h.patchJob(ctx, p.JobID, false, jobErrorResult(err.Error()))
	}
	return h.patchJob(ctx, p.JobID, true, []byte(`{"snapshotted":true}`))
}

// HandleClaimed runs a job row already claimed via claim_pending_jobs_v1 (scheduler/billing).
func (h *Handler) HandleClaimed(ctx context.Context, jobID int64, command string, clusterID int64, arguments json.RawMessage, requestID string) error {
	if requestID == "" {
		requestID = fmt.Sprintf("job-%d", jobID)
	}
	return h.idem.Run(ctx, "volume-"+requestID, func(ctx context.Context) error {
		p := model.VolumeJobMsg{
			RequestID: requestID,
			Command:   command,
			ClusterID: clusterID,
			Arguments: arguments,
			JobID:     jobID,
		}
		deriveFields(&p)
		err := h.dispatch(ctx, p)
		return err
	})
}
