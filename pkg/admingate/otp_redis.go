package admingate

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const otpKeyPrefix = "admin:otp:"

// RedisOTPStore stores OTP hashes in Redis.
type RedisOTPStore struct {
	client *redis.Client
}

func NewRedisOTPStore(url string) (*RedisOTPStore, error) {
	opt, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("redis url: %w", err)
	}
	client := redis.NewClient(opt)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis ping: %w", err)
	}
	return &RedisOTPStore{client: client}, nil
}

func (s *RedisOTPStore) Close() error {
	return s.client.Close()
}

func (s *RedisOTPStore) Save(ctx context.Context, email, code string, ttl time.Duration) error {
	key := otpKeyPrefix + email
	return s.client.Set(ctx, key, hashOTP(code), ttl).Err()
}

func (s *RedisOTPStore) Verify(ctx context.Context, email, code string) (bool, error) {
	key := otpKeyPrefix + email
	got, err := s.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if got != hashOTP(code) {
		return false, nil
	}
	_ = s.client.Del(ctx, key).Err()
	return true, nil
}
