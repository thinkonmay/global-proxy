package runtime

import (
	"context"

	"github.com/thinkonmay/thinkshare-daemon/persistent"
	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

// RollbackLeases releases addon leases claimed during /new when deploy never succeeds.
func RollbackLeases(ctx context.Context, pr *postgrest.Client, session *persistent.WorkerSession) {
	if pr == nil || session == nil {
		return
	}
	if session.App != nil && session.App.Keepalive != nil && session.App.Keepalive.KeepaliveID > 0 {
		_ = pr.RPC(ctx, "unclaim_v1", map[string]any{
			"keepaliveid": session.App.Keepalive.KeepaliveID,
		}, nil)
	}
}
