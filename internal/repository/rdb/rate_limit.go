package rdb

import (
	"context"
	"fmt"
	"time"

	"github.com/open-stash/sentinel/internal/repository"
	redispkg "github.com/open-stash/sentinel/pkg/redis"
)

type rateLimitRepo struct {
	redis    redispkg.Client
	capacity uint64
	// refillRate is capacity / window in seconds, giving tokens-per-second.
	// e.g. 5 attempts per 15 min = 5 / 900 ≈ 0.00556 tokens/sec
	refillRate float64
}

// NewRateLimitRepository creates a token-bucket rate limiter backed by Redis.
// capacity and window come from AuthConfig (rate_limit_attempts, rate_limit_window).
func NewRateLimitRepository(redis redispkg.Client, capacity uint64, window time.Duration) repository.RateLimitRepository {
	return &rateLimitRepo{
		redis:      redis,
		capacity:   capacity,
		refillRate: float64(capacity) / window.Seconds(),
	}
}

func (r *rateLimitRepo) Allow(ctx context.Context, ip string) (bool, time.Duration, error) {
	key := fmt.Sprintf("ratelimit:login:%s", ip)
	result, err := r.redis.RateLimit(ctx, key, r.capacity, r.refillRate)
	if err != nil {
		return false, 0, fmt.Errorf("rate limit check: %w", err)
	}

	if !result.Allowed {
		return false, time.Duration(result.RetryAfterSeconds) * time.Second, nil
	}
	return true, 0, nil
}

func (r *rateLimitRepo) Reset(ctx context.Context, ip string) error {
	key := fmt.Sprintf("ratelimit:login:%s", ip)
	return r.redis.DeleteRateLimit(ctx, key)
}
