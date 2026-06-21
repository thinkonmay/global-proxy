package admingate

import (
	"context"
	"time"
)

// IPAllowStore records client IPs temporarily allowed through the admin gate.
type IPAllowStore interface {
	GrantIP(ctx context.Context, ip string, ttl time.Duration) error
	IPAllowed(ctx context.Context, ip string) (bool, error)
}
