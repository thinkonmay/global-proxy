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
	unclaimKeepalive(ctx, pr, keepaliveID(session.GetApp()))
	unclaimKeepalive(ctx, pr, keepaliveID(session.GetS3Bucket()))
}

func keepaliveID(holder interface{ GetKeepalive() *persistent.Keepalive }) int32 {
	if holder == nil {
		return 0
	}
	ka := holder.GetKeepalive()
	if ka == nil {
		return 0
	}
	return ka.GetKeepaliveID()
}

func unclaimKeepalive(ctx context.Context, pr *postgrest.Client, id int32) {
	if id <= 0 {
		return
	}
	_ = pr.RPC(ctx, "unclaim_v1", map[string]any{
		"keepaliveid": id,
	}, nil)
}
