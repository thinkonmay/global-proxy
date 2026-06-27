package runtime

import (
	"context"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

// UnclaimUserSessions clears runtime addon leases for email (PB deleteUserSessionByUserID).
func UnclaimUserSessions(ctx context.Context, pr *postgrest.Client, email string) {
	if pr == nil || email == "" {
		return
	}
	_ = pr.RPC(ctx, "unclaim_user_runtime_sessions_v1", map[string]any{
		"email": email,
	}, nil)
}
