package superuser

import (
	"context"
	"fmt"
	"strings"

	"github.com/thinkonmay/global-proxy/api/pkg/postgrest"
)

// IsEmail reports whether email is in events.constant superusers (Track C5; replaces PB _superusers).
func IsEmail(ctx context.Context, pr *postgrest.Client, email string) (bool, error) {
	if pr == nil {
		return false, fmt.Errorf("postgrest unavailable")
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return false, nil
	}
	var ok bool
	if err := pr.RPC(ctx, "is_superuser_email_v1", map[string]any{"p_email": email}, &ok); err != nil {
		return false, err
	}
	return ok, nil
}
