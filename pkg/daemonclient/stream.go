package daemonclient

import (
	"context"
	"net/http"
	"sync"

	"github.com/thinkonmay/thinkshare-daemon/persistent"
	"github.com/thinkonmay/global-proxy/api/pkg/cluster"
	"github.com/thinkonmay/global-proxy/api/pkg/sse"
	"github.com/thinkonmay/global-proxy/api/pkg/workerinfor"
)

// RelayNewStream copies gRPC NewStream events to an HTTP SSE response.
// When volumeIDs is non-empty, the final WorkerInfor is filtered (PB filterVolume).
func RelayNewStream(ctx context.Context, w http.ResponseWriter, stream persistent.Daemon_NewStreamClient, volumeIDs []string) error {
	sse.WriteHeaders(w)
	fl, _ := w.(http.Flusher)
	index := 0
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		res, err := stream.Recv()
		if err != nil {
			index++
			_ = sse.WriteEvent(w, index, &persistent.NewResult{
				Status: err.Error(),
				Code:   404,
			})
			if fl != nil {
				fl.Flush()
			}
			return err
		}
		if res.Info != nil && len(volumeIDs) > 0 {
			filtered := workerinfor.Filter(res.Info, volumeIDs)
			res = &persistent.NewResult{
				Status: res.Status,
				Code:   res.Code,
				Info:   filtered,
			}
		}
		index++
		if err := sse.WriteEvent(w, index, res); err != nil {
			return err
		}
		if fl != nil {
			fl.Flush()
		}
		if res.Info != nil {
			return nil
		}
	}
}

// RelayAllocateStream copies gRPC Allocate progress to SSE (reallocate/template).
// finished is true when allocate completed without error.
func RelayAllocateStream(ctx context.Context, w http.ResponseWriter, stream persistent.Daemon_AllocateClient) (finished bool, err error) {
	sse.WriteHeaders(w)
	fl, _ := w.(http.Flusher)
	index := 0
	for {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		default:
		}
		res, err := stream.Recv()
		if err != nil {
			index++
			_ = sse.WriteEvent(w, index, map[string]any{"error": err.Error()})
			if fl != nil {
				fl.Flush()
			}
			return false, nil
		}
		index++
		if res.Finished {
			if err := sse.WriteEvent(w, index, map[string]any{"finished": true}); err != nil {
				return false, err
			}
			if fl != nil {
				fl.Flush()
			}
			return true, nil
		}
		if err := sse.WriteEvent(w, index, map[string]any{"percentage": res.Percentage}); err != nil {
			return false, err
		}
		if fl != nil {
			fl.Flush()
		}
	}
}

// RelayInfoStream fans out InfoStream across user clusters and relays merged snapshots.
func (c *Client) RelayInfoStream(ctx context.Context, w http.ResponseWriter, email string) error {
	groups, err := cluster.UserVolumeGroups(ctx, c.pr, email)
	if err != nil {
		return err
	}
	sse.WriteHeaders(w)
	fl, _ := w.(http.Flusher)
	if len(groups) == 0 {
		return sse.WriteEvent(w, 1, &persistent.WorkerInfor{})
	}

	type sub struct {
		stream persistent.Daemon_InfoStreamClient
		vols   []string
	}
	var subs []sub
	for clusterID, vols := range groups {
		stream, err := c.InfoStream(ctx, clusterID)
		if err != nil {
			continue
		}
		subs = append(subs, sub{stream: stream, vols: vols})
	}
	if len(subs) == 0 {
		return sse.WriteEvent(w, 1, &persistent.WorkerInfor{})
	}

	var (
		mu    sync.Mutex
		parts = make([]*persistent.WorkerInfor, len(subs))
		index int
	)
	writeMerged := func() {
		var mergedParts []*persistent.WorkerInfor
		for _, p := range parts {
			if p != nil {
				mergedParts = append(mergedParts, p)
			}
		}
		index++
		_ = sse.WriteEvent(w, index, workerinfor.Merge(mergedParts))
		if fl != nil {
			fl.Flush()
		}
	}

	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	for i := range subs {
		i := i
		go func() {
			for {
				select {
				case <-childCtx.Done():
					return
				default:
				}
				info, err := subs[i].stream.Recv()
				if err != nil {
					cancel()
					return
				}
				mu.Lock()
				parts[i] = workerinfor.Filter(info, subs[i].vols)
				mu.Unlock()
				writeMerged()
			}
		}()
	}
	<-ctx.Done()
	return ctx.Err()
}

// RelayTemplateStream runs rename then allocate SSE (superuser template set).
func RelayTemplateStream(ctx context.Context, w http.ResponseWriter, c *Client, clusterID int64, rename *persistent.RenameRequest, allocate *persistent.AllocateRequest) error {
	sse.WriteHeaders(w)
	fl, _ := w.(http.Flusher)
	index := 0

	if err := c.Rename(ctx, clusterID, rename); err != nil {
		index++
		_ = sse.WriteEvent(w, index, map[string]any{"error": "rename failed: " + err.Error()})
		if fl != nil {
			fl.Flush()
		}
		return nil
	}
	index++
	if err := sse.WriteEvent(w, index, map[string]any{"phase": "template_created", "percentage": 0}); err != nil {
		return err
	}
	if fl != nil {
		fl.Flush()
	}

	stream, err := c.AllocateStream(ctx, clusterID, allocate)
	if err != nil {
		index++
		_ = sse.WriteEvent(w, index, map[string]any{"error": "allocate failed: " + err.Error()})
		if fl != nil {
			fl.Flush()
		}
		return nil
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		res, err := stream.Recv()
		if err != nil {
			index++
			_ = sse.WriteEvent(w, index, map[string]any{"error": err.Error()})
			if fl != nil {
				fl.Flush()
			}
			return nil
		}
		index++
		if res.Finished {
			if err := sse.WriteEvent(w, index, map[string]any{"finished": true, "percentage": 100}); err != nil {
				return err
			}
			if fl != nil {
				fl.Flush()
			}
			return nil
		}
		if err := sse.WriteEvent(w, index, map[string]any{"phase": "resetting_volume", "percentage": res.Percentage}); err != nil {
			return err
		}
		if fl != nil {
			fl.Flush()
		}
	}
}
