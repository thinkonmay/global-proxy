package usage

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const dedupKeyPrefix = "usage:dedup:"

// Dedup prevents double-charging when the collector retries within a tick window.
type Dedup struct {
	client *redis.Client
}

func NewDedup(redisURL string) (*Dedup, error) {
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("redis url: %w", err)
	}
	client := redis.NewClient(opt)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis ping: %w", err)
	}
	return &Dedup{client: client}, nil
}

func (d *Dedup) Close() error {
	return d.client.Close()
}

// Claim returns true when key was not seen recently (caller should bill/emit).
func (d *Dedup) Claim(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	ok, err := d.client.SetNX(ctx, dedupKeyPrefix+key, "1", ttl).Result()
	if err != nil {
		return false, err
	}
	return ok, nil
}
