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

type emailVerificationRepo struct {
	q *db.Queries
}

func NewEmailVerificationRepository(q *db.Queries) repository.EmailVerificationRepository {
	return &emailVerificationRepo{q: q}
}

func (r *emailVerificationRepo) Create(ctx context.Context, token, userID string, expiresAt time.Time) error {
	pgID, err := parseUUID(userID)
	if err != nil {
		return err
	}
	return r.q.CreateEmailVerification(ctx, db.CreateEmailVerificationParams{
		Token:     token,
		UserID:    pgID,
		ExpiresAt: pgtype.Timestamptz{Time: expiresAt, Valid: true},
	})
}

func (r *emailVerificationRepo) Get(ctx context.Context, token string) (*repository.EmailVerification, error) {
	ev, err := r.q.GetEmailVerification(ctx, token)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("email verification repo: get: %w", err)
	}

	result := &repository.EmailVerification{
		Token:  ev.Token,
		UserID: uuid.UUID(ev.UserID.Bytes).String(),
	}
	if ev.ExpiresAt.Valid {
		result.ExpiresAt = ev.ExpiresAt.Time
	}
	if ev.UsedAt.Valid {
		t := ev.UsedAt.Time
		result.UsedAt = &t
	}
	if ev.CreatedAt.Valid {
		result.CreatedAt = ev.CreatedAt.Time
	}
	return result, nil
}

func (r *emailVerificationRepo) MarkUsed(ctx context.Context, token string) error {
	return r.q.MarkEmailVerificationUsed(ctx, token)
}

func (r *emailVerificationRepo) DeleteExpired(ctx context.Context) error {
	return r.q.DeleteExpiredEmailVerifications(ctx)
}
