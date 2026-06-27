package daemonclient

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/thinkonmay/thinkshare-daemon/persistent"
)

// BuildAllocateRequest picks a template volume and pool (mirrors node PB volumeAllocate).
func BuildAllocateRequest(info *persistent.WorkerInfor, id, template string, transient bool) (*persistent.AllocateRequest, error) {
	if info == nil {
		return nil, fmt.Errorf("cluster info is nil")
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, fmt.Errorf("volume id required")
	}
	for _, vol := range info.Volumes {
		if vol != nil && vol.Name == id {
			return nil, fmt.Errorf("volume %s already exist", id)
		}
	}

	acceptedPool := []string{"unified_data"}
	if !transient {
		acceptedPool = append(acceptedPool, "user_data")
	}

	template = normalizeTemplateName(template)
	available := []*persistent.Volume{}
	pools := []*persistent.Pool{}
	for _, p := range info.Pools {
		if p != nil && slices.Contains(acceptedPool, p.Name) {
			pools = append(pools, p)
		}
	}

	retry := false
retry:
	for _, vol := range info.Volumes {
		if vol != nil && vol.Name == template {
			available = append(available, vol)
		}
	}
	if len(available) == 0 && !retry {
		template = normalizeTemplateName("win11")
		retry = true
		goto retry
	}
	if len(available) == 0 {
		return nil, fmt.Errorf("source template not exist %s", template)
	}

	slices.SortFunc(pools, func(a, b *persistent.Pool) int {
		return int(b.Size - a.Size)
	})

	var baseTemplate *persistent.Volume
	for _, pool := range pools {
		for _, option := range available {
			if option.Node == pool.Node {
				baseTemplate = option
				goto found
			}
		}
	}
	return nil, fmt.Errorf("no pool contains source volume %s", template)

found:
	return &persistent.AllocateRequest{
		Source: baseTemplate,
		Destination: &persistent.Volume{
			Name:      id,
			Node:      baseTemplate.Node,
			Transient: transient,
		},
		Override: false,
	}, nil
}

// AllocateVolume clones template to id on clusterID and waits for completion.
func (c *Client) AllocateVolume(ctx context.Context, clusterID int64, id, template string, transient bool) error {
	info, err := c.InfoCluster(ctx, clusterID)
	if err != nil {
		return err
	}
	req, err := BuildAllocateRequest(info, id, template, transient)
	if err != nil {
		return err
	}
	stream, err := c.AllocateStream(ctx, clusterID, req)
	if err != nil {
		return err
	}
	return WaitAllocateStream(ctx, stream)
}

// WaitAllocateStream blocks until allocate finishes or ctx is cancelled.
func WaitAllocateStream(ctx context.Context, stream persistent.Daemon_AllocateClient) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		status, err := stream.Recv()
		if err != nil {
			return err
		}
		if status.Finished {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
}
