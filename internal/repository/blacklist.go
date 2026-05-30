package repository

import (
	"context"
	"time"
)

// BlacklistRepository stores revoked JWT JTIs until they naturally expire.
type BlacklistRepository interface {
	Add(ctx context.Context, jti string, ttl time.Duration) error
	Contains(ctx context.Context, jti string) (bool, error)
}
