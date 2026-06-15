package repository

import (
	"context"
	"time"

	"github.com/open-stash/sentinel/internal/domain"
)

type UserRepository interface {
	Create(ctx context.Context, name, email, passwordHash string, role domain.Role) (*domain.User, error)
	GetByID(ctx context.Context, id string) (*domain.User, error)
	GetByEmail(ctx context.Context, email string) (*domain.User, error)
	UpdateProfile(ctx context.Context, id, name, bio string) (*domain.User, error)
	UpdateEmailVerified(ctx context.Context, id string) error
	UpdatePassword(ctx context.Context, id, passwordHash string) error
	UpdateTOTPSecret(ctx context.Context, id, secret string, enabled bool) error
	IncrementFailedLogins(ctx context.Context, id string) error
	LockUser(ctx context.Context, id string, until time.Time) error
	ResetFailedLogins(ctx context.Context, id string) error
}
