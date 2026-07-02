package cluster

import (
	"context"
	"fmt"
	"strings"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

// UserEligibleForRuntimeStream reports whether live runtime info is meaningful for
// the user (active subscription and/or at least one volume). Users with neither
// should not open long-lived InfoStream connections.
func UserEligibleForRuntimeStream(ctx context.Context, pr *postgrest.Client, email string) (bool, error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return false, fmt.Errorf("email required")
	}
	if pr == nil {
		return false, fmt.Errorf("postgrest unavailable")
	}

	groups, err := UserVolumeGroups(ctx, pr, email)
	if err != nil {
		return false, err
	}
	if len(groups) > 0 {
		return true, nil
	}

	var machines []struct {
		ID int64 `json:"id"`
	}
	if err := pr.RPC(ctx, "get_machines", map[string]any{"p_email": email}, &machines); err != nil {
		return false, err
	}
	return len(machines) > 0, nil
}
