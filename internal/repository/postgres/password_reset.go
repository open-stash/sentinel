package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/open-stash/sentinel/internal/repository"
	db "github.com/open-stash/sentinel/pkg/db"
)

type passwordResetRepo struct {
	q *db.Queries
}

func NewPasswordResetRepository(q *db.Queries) repository.PasswordResetRepository {
	return &passwordResetRepo{q: q}
}

func (r *passwordResetRepo) Create(ctx context.Context, token, userID string, expiresAt time.Time) error {
	pgID, err := parseUUID(userID)
	if err != nil {
		return err
	}
	return r.q.CreatePasswordReset(ctx, db.CreatePasswordResetParams{
		Token:     token,
		UserID:    pgID,
		ExpiresAt: pgtype.Timestamptz{Time: expiresAt, Valid: true},
	})
}

func (r *passwordResetRepo) Get(ctx context.Context, token string) (*repository.PasswordReset, error) {
	pr, err := r.q.GetPasswordReset(ctx, token)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("password reset repo: get: %w", err)
	}

	result := &repository.PasswordReset{
		Token:  pr.Token,
		UserID: uuid.UUID(pr.UserID.Bytes).String(),
	}
	if pr.ExpiresAt.Valid {
		result.ExpiresAt = pr.ExpiresAt.Time
	}
	if pr.UsedAt.Valid {
		t := pr.UsedAt.Time
		result.UsedAt = &t
	}
	if pr.CreatedAt.Valid {
		result.CreatedAt = pr.CreatedAt.Time
	}
	return result, nil
}

func (r *passwordResetRepo) MarkUsed(ctx context.Context, token string) error {
	return r.q.MarkPasswordResetUsed(ctx, token)
}

func (r *passwordResetRepo) DeleteExpired(ctx context.Context) error {
	return r.q.DeleteExpiredPasswordResets(ctx)
}
