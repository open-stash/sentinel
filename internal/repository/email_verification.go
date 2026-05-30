package repository

import (
	"context"
	"time"
)

type EmailVerification struct {
	Token     string
	UserID    string
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

type EmailVerificationRepository interface {
	Create(ctx context.Context, token, userID string, expiresAt time.Time) error
	Get(ctx context.Context, token string) (*EmailVerification, error)
	MarkUsed(ctx context.Context, token string) error
	DeleteExpired(ctx context.Context) error
}
