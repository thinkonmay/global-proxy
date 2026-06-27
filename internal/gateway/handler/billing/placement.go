package billing

import (
	"context"
	"strings"

	"github.com/thinkonmay/global-proxy/api/pkg/cluster"
)

func (h *Handler) resolveClusterDomain(ctx context.Context, explicit string) (string, error) {
	if domain := strings.TrimSpace(explicit); domain != "" {
		return domain, nil
	}
	return cluster.PickPlacementDomain(ctx, h.pr)
}
