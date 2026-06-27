package pwa

import (
	"context"

	"github.com/thinkonmay/global-proxy/api/pkg/superuser"
)

func (h *Handler) isSuperuserEmail(ctx context.Context, email string) (bool, error) {
	return superuser.IsEmail(ctx, h.pr, email)
}
