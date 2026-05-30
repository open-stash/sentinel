package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	minLockTTL = 10 * time.Second
	maxLockTTL = 30 * time.Second
)

// Client is the interface for all Redis operations used by the auth service.
type Client interface {
	Set(ctx context.Context, key string, value any, ttl time.Duration) error
	Get(ctx context.Context, key string) (string, error) // returns ErrNotFound on miss
	Exists(ctx context.Context, key string) (bool, error)
	SetNX(ctx context.Context, key string, value any, ttl time.Duration) (bool, error)
	Delete(ctx context.Context, key string) error
	Incr(ctx context.Context, key string) (int64, error)
	Expire(ctx context.Context, key string, ttl time.Duration) error
	AcquireLock(ctx context.Context, key string, expiry time.Duration) (bool, error)
	ReleaseLock(ctx context.Context, key string) error
	ExecuteRatelimiterScript(ctx context.Context, cfg *RatelimiterConfig) (*RatelimiterResult, error)

	// RateLimit runs the token-bucket Lua script for the given logical key.
	// key is automatically namespaced under the client's key prefix.
	RateLimit(ctx context.Context, key string, capacity uint64, refillRatePerSec float64) (*RatelimiterResult, error)

	// DeleteRateLimit removes the token-bucket state for the given logical key.
	// Call this after a successful login to reset the bucket for that key.
	DeleteRateLimit(ctx context.Context, key string) error
}

type clientImpl struct {
	cfg *Config
	rdb *redis.Client
}

// NewClient connects to Redis and verifies connectivity.
func NewClient(ctx context.Context, cfg *Config) (Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
	})

	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis: ping %s: %w", cfg.Addr, err)
	}

	return &clientImpl{cfg: cfg, rdb: rdb}, nil
}

func (c *clientImpl) Set(ctx context.Context, key string, value any, ttl time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("redis: marshal value for key %q: %w", key, err)
	}
	return c.rdb.Set(ctx, c.prefixed(key), data, ttl).Err()
}

func (c *clientImpl) Get(ctx context.Context, key string) (string, error) {
	val, err := c.rdb.Get(ctx, c.prefixed(key)).Result()
	if errors.Is(err, redis.Nil) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("redis: get %q: %w", key, err)
	}
	return val, nil
}

func (c *clientImpl) Exists(ctx context.Context, key string) (bool, error) {
	n, err := c.rdb.Exists(ctx, c.prefixed(key)).Result()
	if err != nil {
		return false, fmt.Errorf("redis: exists %q: %w", key, err)
	}
	return n > 0, nil
}

func (c *clientImpl) SetNX(ctx context.Context, key string, value any, ttl time.Duration) (bool, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return false, fmt.Errorf("redis: marshal value for key %q: %w", key, err)
	}
	return c.rdb.SetNX(ctx, c.prefixed(key), data, ttl).Result()
}

func (c *clientImpl) Delete(ctx context.Context, key string) error {
	return c.rdb.Del(ctx, c.prefixed(key)).Err()
}

func (c *clientImpl) Incr(ctx context.Context, key string) (int64, error) {
	n, err := c.rdb.Incr(ctx, c.prefixed(key)).Result()
	if err != nil {
		return 0, fmt.Errorf("redis: incr %q: %w", key, err)
	}
	return n, nil
}

func (c *clientImpl) Expire(ctx context.Context, key string, ttl time.Duration) error {
	return c.rdb.Expire(ctx, c.prefixed(key), ttl).Err()
}

func (c *clientImpl) AcquireLock(ctx context.Context, key string, expiry time.Duration) (bool, error) {
	if expiry < minLockTTL {
		expiry = minLockTTL
	}
	if expiry > maxLockTTL {
		expiry = maxLockTTL
	}
	return c.rdb.SetNX(ctx, c.prefixed(key), "locked", expiry).Result()
}

func (c *clientImpl) ReleaseLock(ctx context.Context, key string) error {
	return c.rdb.Del(ctx, c.prefixed(key)).Err()
}

func (c *clientImpl) ExecuteRatelimiterScript(ctx context.Context, cfg *RatelimiterConfig) (*RatelimiterResult, error) {
	res, err := ratelimiterScript.Run(ctx, c.rdb, []string{
		cfg.TokensKey,
		cfg.TimestampKey,
	}, cfg.Capacity, cfg.RefillRatePerSecond, time.Now().UnixMilli()).Result()
	if err != nil {
		return nil, fmt.Errorf("redis: ratelimiter script: %w", err)
	}

	arr, ok := res.([]any)
	if !ok || len(arr) != 3 {
		return nil, fmt.Errorf("redis: unexpected ratelimiter result: %v", res)
	}

	return &RatelimiterResult{
		Allowed:           arr[0].(int64) == 1,
		TokensLeft:        arr[1].(int64),
		RetryAfterSeconds: arr[2].(int64),
	}, nil
}

func (c *clientImpl) RateLimit(ctx context.Context, key string, capacity uint64, refillRatePerSec float64) (*RatelimiterResult, error) {
	tokensKey := c.prefixed(key + ":tokens")
	tsKey := c.prefixed(key + ":ts")

	res, err := ratelimiterScript.Run(ctx, c.rdb, []string{tokensKey, tsKey},
		capacity, refillRatePerSec, time.Now().UnixMilli()).Result()
	if err != nil {
		return nil, fmt.Errorf("redis: ratelimit %q: %w", key, err)
	}

	arr, ok := res.([]any)
	if !ok || len(arr) != 3 {
		return nil, fmt.Errorf("redis: unexpected ratelimiter result: %v", res)
	}

	return &RatelimiterResult{
		Allowed:           arr[0].(int64) == 1,
		TokensLeft:        arr[1].(int64),
		RetryAfterSeconds: arr[2].(int64),
	}, nil
}

func (c *clientImpl) DeleteRateLimit(ctx context.Context, key string) error {
	tokensKey := c.prefixed(key + ":tokens")
	tsKey := c.prefixed(key + ":ts")
	return c.rdb.Del(ctx, tokensKey, tsKey).Err()
}

// prefixed returns the key namespaced under the configured prefix.
func (c *clientImpl) prefixed(key string) string {
	return fmt.Sprintf("%s:%s", c.cfg.KeyPrefix, key)
}
