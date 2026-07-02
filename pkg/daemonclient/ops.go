package daemonclient

import (
	"context"
	"fmt"
	"strings"

	"github.com/thinkonmay/global-proxy/api/pkg/audit"
	"github.com/thinkonmay/thinkshare-daemon/persistent"
	"google.golang.org/grpc/metadata"
)

func traceCtx(ctx context.Context) context.Context {
	return audit.OutgoingGRPCMetadata(ctx)
}

// Daemon returns a gRPC client for clusterID.
func (c *Client) Daemon(ctx context.Context, clusterID int64) (persistent.DaemonClient, error) {
	conn, err := c.conn(ctx, clusterID)
	if err != nil {
		return nil, err
	}
	return persistent.NewDaemonClient(conn), nil
}

// InfoCluster returns unfiltered WorkerInfor from one cluster.
func (c *Client) InfoCluster(ctx context.Context, clusterID int64) (*persistent.WorkerInfor, error) {
	return c.infoCluster(ctx, clusterID)
}

// NewStream opens a deploy progress stream on clusterID.
func (c *Client) NewStream(ctx context.Context, clusterID int64, session *persistent.WorkerSession) (persistent.Daemon_NewStreamClient, error) {
	cli, err := c.Daemon(ctx, clusterID)
	if err != nil {
		return nil, err
	}
	return cli.NewStream(traceCtx(ctx), session)
}

// CloseSession ends a VM session on clusterID with user-close audit metadata (AUD-T2).
func (c *Client) CloseSession(ctx context.Context, clusterID int64, session *persistent.WorkerSession) (*persistent.WorkerInfor, error) {
	cli, err := c.Daemon(ctx, clusterID)
	if err != nil {
		return nil, err
	}
	ctx = traceCtx(ctx)
	ctx = metadata.AppendToOutgoingContext(ctx,
		"x-session-close-initiator", "user",
		"x-session-audit-event-type", "session.user_close",
	)
	return cli.Close(ctx, session)
}

// RestartSession restarts a VM session on clusterID.
func (c *Client) RestartSession(ctx context.Context, clusterID int64, session *persistent.WorkerSession) error {
	cli, err := c.Daemon(ctx, clusterID)
	if err != nil {
		return err
	}
	_, err = cli.Restart(traceCtx(ctx), session)
	return err
}

// AllocateStream opens a volume clone progress stream.
func (c *Client) AllocateStream(ctx context.Context, clusterID int64, req *persistent.AllocateRequest) (persistent.Daemon_AllocateClient, error) {
	cli, err := c.Daemon(ctx, clusterID)
	if err != nil {
		return nil, err
	}
	return cli.Allocate(traceCtx(ctx), req)
}

// ListSnapshots lists MFS snapshots for a volume.
func (c *Client) ListSnapshots(ctx context.Context, clusterID int64, volumeID string) (*persistent.SnapshotListResult, error) {
	cli, err := c.Daemon(ctx, clusterID)
	if err != nil {
		return nil, err
	}
	return cli.ListSnapshots(traceCtx(ctx), &persistent.SnapshotRequest{VolumeId: volumeID})
}

// RestoreSnapshot restores a named snapshot.
func (c *Client) RestoreSnapshot(ctx context.Context, clusterID int64, volumeID, snapshotName string) error {
	cli, err := c.Daemon(ctx, clusterID)
	if err != nil {
		return err
	}
	_, err = cli.RestoreSnapshot(traceCtx(ctx), &persistent.RestoreRequest{
		VolumeId:     volumeID,
		SnapshotName: snapshotName,
	})
	return err
}

// DeallocateVolume removes a volume from cluster storage.
func (c *Client) DeallocateVolume(ctx context.Context, clusterID int64, volumeID string) error {
	info, err := c.InfoCluster(ctx, clusterID)
	if err != nil {
		return err
	}
	var source *persistent.Volume
	for _, vol := range info.Volumes {
		if vol != nil && vol.Name == volumeID {
			source = vol
			break
		}
	}
	if source == nil {
		return fmt.Errorf("volume not exist %s", volumeID)
	}
	cli, err := c.Daemon(ctx, clusterID)
	if err != nil {
		return err
	}
	_, err = cli.Deallocate(traceCtx(ctx), source)
	return err
}

// SnapshotAll snapshots the given volume ids on clusterID (daily cron offload).
func (c *Client) SnapshotAll(ctx context.Context, clusterID int64, volumeIDs []string) error {
	if len(volumeIDs) == 0 {
		return nil
	}
	cli, err := c.Daemon(ctx, clusterID)
	if err != nil {
		return err
	}
	_, err = cli.SnapshotAll(traceCtx(ctx), &persistent.SnapshotAllRequest{VolumeIds: volumeIDs})
	return err
}

// SnapshotVolume toggles snapshot cron for a volume (enable when name non-empty).
func (c *Client) SnapshotVolume(ctx context.Context, clusterID int64, volumeID string) error {
	cli, err := c.Daemon(ctx, clusterID)
	if err != nil {
		return err
	}
	_, err = cli.SnapshotVolume(traceCtx(ctx), &persistent.SnapshotRequest{VolumeId: volumeID})
	return err
}

// InfoStream opens a live dashboard stream on clusterID.
func (c *Client) InfoStream(ctx context.Context, clusterID int64) (persistent.Daemon_InfoStreamClient, error) {
	cli, err := c.Daemon(ctx, clusterID)
	if err != nil {
		return nil, err
	}
	return cli.InfoStream(traceCtx(ctx), &persistent.Empty{})
}

// Rename renames a volume on clusterID.
func (c *Client) Rename(ctx context.Context, clusterID int64, req *persistent.RenameRequest) error {
	cli, err := c.Daemon(ctx, clusterID)
	if err != nil {
		return err
	}
	_, err = cli.Rename(traceCtx(ctx), req)
	return err
}

// Deallocate removes a volume on clusterID.
func (c *Client) Deallocate(ctx context.Context, clusterID int64, vol *persistent.Volume) error {
	cli, err := c.Daemon(ctx, clusterID)
	if err != nil {
		return err
	}
	_, err = cli.Deallocate(traceCtx(ctx), vol)
	return err
}

// BuildTemplateRequest constructs rename+allocate for superuser template set (mirrors PB).
func BuildTemplateRequest(info *persistent.WorkerInfor, volumeID, templateName string) (*persistent.RenameRequest, *persistent.AllocateRequest, error) {
	var userVol *persistent.Volume
	for _, vol := range info.Volumes {
		if vol != nil && vol.Name == volumeID {
			userVol = vol
			break
		}
	}
	if userVol == nil {
		return nil, nil, fmt.Errorf("volume not found %s", volumeID)
	}
	var win11 *persistent.Volume
	for _, vol := range info.Volumes {
		if vol != nil && vol.Name == "win11.template" && vol.Node == userVol.Node {
			win11 = vol
			break
		}
	}
	if win11 == nil {
		return nil, nil, fmt.Errorf("win11.template not found on the same node")
	}
	destName := strings.TrimSpace(templateName) + ".template"
	rename := &persistent.RenameRequest{
		Source:      volumeID,
		Destination: destName,
		Node:        userVol.Node,
	}
	allocate := &persistent.AllocateRequest{
		Source: win11,
		Destination: &persistent.Volume{
			Name: volumeID,
			Node: userVol.Node,
			Pool: userVol.Pool,
		},
		Override: false,
	}
	return rename, allocate, nil
}

// BuildReallocateRequest constructs an AllocateRequest from cluster Info (mirrors PB reallocate).
func BuildReallocateRequest(info *persistent.WorkerInfor, destID, sourceName string) (*persistent.AllocateRequest, error) {
	sourceName = normalizeTemplateName(sourceName)
	var dest, source *persistent.Volume
	for _, vol := range info.Volumes {
		if vol == nil {
			continue
		}
		if vol.Name == destID {
			dest = vol
		}
	}
	if dest == nil {
		return nil, fmt.Errorf("destination volume not exist %s", destID)
	}
	for _, vol := range info.Volumes {
		if vol != nil && vol.Name == sourceName && vol.Node == dest.Node {
			source = vol
			break
		}
	}
	if source == nil {
		return nil, fmt.Errorf("source template not exist %s", sourceName)
	}
	return &persistent.AllocateRequest{
		Source:      source,
		Destination: dest,
		Override:    true,
	}, nil
}

func normalizeTemplateName(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasSuffix(s, ".template") {
		return s
	}
	return s + ".template"
}
