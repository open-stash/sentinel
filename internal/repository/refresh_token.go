package repository

import (
	"context"
	"time"
)

type RefreshToken struct {
	Token     string
	UserID    string
	ExpiresAt time.Time
	IPAddress string
	UserAgent string
	CreatedAt time.Time
}

type RefreshTokenRepository interface {
	Store(ctx context.Context, token, userID, ipAddress, userAgent string, expiresAt time.Time) error
	Get(ctx context.Context, token string) (*RefreshToken, error)
	Delete(ctx context.Context, token string) error
	DeleteAllForUser(ctx context.Context, userID string) error
	CountActiveForUser(ctx context.Context, userID string) (int64, error)
}
