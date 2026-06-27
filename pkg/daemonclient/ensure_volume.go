package daemonclient

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/thinkonmay/thinkshare-daemon/persistent"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
	"github.com/thinkonmay/global-proxy/api/pkg/volumeconfig"
)

// VolumeExistsOnCluster reports whether volID appears in cluster WorkerInfor.
func VolumeExistsOnCluster(info *persistent.WorkerInfor, volID string) bool {
	volID = strings.TrimSpace(volID)
	if volID == "" || info == nil {
		return false
	}
	for _, vol := range info.Volumes {
		if vol != nil && vol.Name == volID {
			return true
		}
	}
	return false
}

// EnsureVolumeAllocated clones a transient volume on the cluster when Postgres has a row but
// on-disk storage was never provisioned or was GC'd (F03 transient allocate, db-migration tdd §5.2.6).
func (c *Client) EnsureVolumeAllocated(
	ctx context.Context,
	pr *postgrest.Client,
	clusterID int64,
	email, volID string,
) error {
	volID = strings.TrimSpace(volID)
	if volID == "" {
		return fmt.Errorf("volume id required")
	}
	info, err := c.InfoCluster(ctx, clusterID)
	if err != nil {
		return err
	}
	if VolumeExistsOnCluster(info, volID) {
		return nil
	}
	if pr == nil {
		return fmt.Errorf("volume %s not found on cluster", volID)
	}
	var cfg json.RawMessage
	if err := pr.RPC(ctx, "lookup_volume_configuration_v1", map[string]any{
		"email":     strings.TrimSpace(email),
		"volume_id": volID,
	}, &cfg); err != nil {
		return err
	}
	conf, err := volumeconfig.Parse(cfg)
	if err != nil {
		return err
	}
	if !conf.TransientEnabled() {
		return fmt.Errorf("volume %s not found on cluster", volID)
	}
	return c.AllocateVolume(ctx, clusterID, volID, strings.TrimSuffix(conf.TemplateName(), ".template"), true)
}
