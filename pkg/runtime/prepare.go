package runtime

import (
	"context"
	"encoding/json"

	"github.com/thinkonmay/thinkshare-daemon/persistent"
	"github.com/thinkonmay/global-proxy/api/pkg/volumeconfig"
)

// PrepareResult is the enriched session context for /new (PB newauth parity).
type PrepareResult struct {
	ClusterID int64
	VolumeIDs []string
	Session   *persistent.WorkerSession
	Config    volumeconfig.Configuration
}

// LookupVolumeConfiguration loads infra.volumes.configuration for a owned volume.
func LookupVolumeConfiguration(ctx context.Context, pr interface {
	RPC(ctx context.Context, name string, args any, dest any) error
}, email, volID string) (volumeconfig.Configuration, error) {
	var raw json.RawMessage
	if err := pr.RPC(ctx, "lookup_volume_configuration_v1", map[string]any{
		"email":     email,
		"volume_id": volID,
	}, &raw); err != nil {
		return volumeconfig.Configuration{}, err
	}
	return volumeconfig.Parse(raw)
}
