// Package cache is a TTL key/value store over opaque bytes, backed by an
// in-memory map now or (later) Redis. For a generic in-process memoizer with
// LRU eviction, see pkg/memo.
package cache

import (
	"context"
	"errors"
	"time"
)

// ErrMiss is returned by Client.Get when the key is absent or expired.
var ErrMiss = errors.New("cache: miss")

type Client interface {
	Get(ctx context.Context, key string) ([]byte, error) // ErrMiss if absent
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	Delete(ctx context.Context, key string) error

	Ping() error
	Close() error
}
