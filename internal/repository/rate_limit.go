package repository

import (
	"context"
	"time"
)

// RateLimitRepository checks and resets per-IP login rate limits.
type RateLimitRepository interface {
	// Allow returns (true, 0, nil) when the request is permitted.
	// Returns (false, retryAfter, nil) when the bucket is empty.
	Allow(ctx context.Context, ip string) (allowed bool, retryAfter time.Duration, err error)

	// Reset removes the token-bucket state for ip — call after a successful login.
	Reset(ctx context.Context, ip string) error
}
