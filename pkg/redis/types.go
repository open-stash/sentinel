package redis

import "errors"

// ErrNotFound is returned by Get when a key does not exist in Redis.
var ErrNotFound = errors.New("redis: key not found")

// RatelimiterConfig configures a single token-bucket rate limit check.
// Keys should be pre-built by the caller using your key naming convention.
//
// Example:
//
//	cfg := &redis.RatelimiterConfig{
//	    TokensKey:           "auth:local:ratelimit:login:192.168.1.1:tokens",
//	    TimestampKey:        "auth:local:ratelimit:login:192.168.1.1:ts",
//	    Capacity:            5,
//	    RefillRatePerSecond: 0.333, // 5 tokens per 15 min
//	}
type RatelimiterConfig struct {
	TokensKey           string
	TimestampKey        string
	Capacity            uint64
	RefillRatePerSecond float64
}

// RatelimiterResult is the outcome of a single token-bucket check.
type RatelimiterResult struct {
	Allowed           bool
	TokensLeft        int64
	RetryAfterSeconds int64
}
