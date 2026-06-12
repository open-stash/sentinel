package repository

import (
	"context"

	"github.com/open-stash/sentinel/internal/domain"
)

type CreateAPIKeyInput struct {
	UserID  string
	Name    string
	KeyHash string
	Prefix  string
}

type APIKeyRepository interface {
	Create(ctx context.Context, in CreateAPIKeyInput) (*domain.APIKey, error)
	// GetByHash returns the (non-revoked) key for a hash, or ErrNotFound.
	GetByHash(ctx context.Context, keyHash string) (*domain.APIKey, error)
	ListByUser(ctx context.Context, userID string) ([]domain.APIKey, error)
	Revoke(ctx context.Context, id, userID string) error
	Touch(ctx context.Context, id string) error
}
