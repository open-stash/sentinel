package repository

import (
	"context"
	"time"
)

type PasswordReset struct {
	Token     string
	UserID    string
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

type PasswordResetRepository interface {
	Create(ctx context.Context, token, userID string, expiresAt time.Time) error
	Get(ctx context.Context, token string) (*PasswordReset, error)
	MarkUsed(ctx context.Context, token string) error
	DeleteExpired(ctx context.Context) error
}
