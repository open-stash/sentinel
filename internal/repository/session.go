package repository

import (
	"context"
	"time"

	"github.com/open-stash/sentinel/internal/domain"
)

// CreateSessionInput carries the data needed to persist a new session.
type CreateSessionInput struct {
	UserID    string
	TokenHash string
	UserAgent string
	Device    string
	Browser   string
	OS        string
	ExpiresAt time.Time
}

type SessionRepository interface {
	Create(ctx context.Context, in CreateSessionInput) (*domain.Session, error)
	GetByTokenHash(ctx context.Context, tokenHash string) (*domain.Session, error)
	GetByID(ctx context.Context, id string) (*domain.Session, error)
	ListActiveByUser(ctx context.Context, userID string) ([]domain.Session, error)
	Touch(ctx context.Context, id string) error
	Revoke(ctx context.Context, id, userID string) error
	RevokeByTokenHash(ctx context.Context, tokenHash string) error
	RevokeOthers(ctx context.Context, userID, keepID string) error
	RevokeAllForUser(ctx context.Context, userID string) error
	DeleteExpired(ctx context.Context) error
}
