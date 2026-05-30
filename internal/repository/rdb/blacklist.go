package rdb

import (
	"context"
	"fmt"
	"time"

	"github.com/open-stash/sentinel/internal/repository"
	redispkg "github.com/open-stash/sentinel/pkg/redis"
)

type blacklistRepo struct {
	redis redispkg.Client
}

func NewBlacklistRepository(redis redispkg.Client) repository.BlacklistRepository {
	return &blacklistRepo{redis: redis}
}

func (r *blacklistRepo) Add(ctx context.Context, jti string, ttl time.Duration) error {
	key := fmt.Sprintf("blacklist:%s", jti)
	if err := r.redis.Set(ctx, key, "1", ttl); err != nil {
		return fmt.Errorf("blacklist: add jti %q: %w", jti, err)
	}
	return nil
}

func (r *blacklistRepo) Contains(ctx context.Context, jti string) (bool, error) {
	key := fmt.Sprintf("blacklist:%s", jti)
	exists, err := r.redis.Exists(ctx, key)
	if err != nil {
		return false, fmt.Errorf("blacklist: check jti %q: %w", jti, err)
	}
	return exists, nil
}
