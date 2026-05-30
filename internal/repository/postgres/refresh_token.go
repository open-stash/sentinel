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

type refreshTokenRepo struct {
	q *db.Queries
}

func NewRefreshTokenRepository(q *db.Queries) repository.RefreshTokenRepository {
	return &refreshTokenRepo{q: q}
}

func (r *refreshTokenRepo) Store(ctx context.Context, token, userID, ipAddress, userAgent string, expiresAt time.Time) error {
	pgID, err := parseUUID(userID)
	if err != nil {
		return err
	}
	return r.q.StoreRefreshToken(ctx, db.StoreRefreshTokenParams{
		Token:     token,
		UserID:    pgID,
		ExpiresAt: pgtype.Timestamptz{Time: expiresAt, Valid: true},
		IpAddress: ipAddress,
		UserAgent: userAgent,
	})
}

func (r *refreshTokenRepo) Get(ctx context.Context, token string) (*repository.RefreshToken, error) {
	rt, err := r.q.GetRefreshToken(ctx, token)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("refresh token repo: get: %w", err)
	}

	result := &repository.RefreshToken{
		Token:     rt.Token,
		UserID:    uuid.UUID(rt.UserID.Bytes).String(),
		IPAddress: rt.IpAddress,
		UserAgent: rt.UserAgent,
	}
	if rt.ExpiresAt.Valid {
		result.ExpiresAt = rt.ExpiresAt.Time
	}
	if rt.CreatedAt.Valid {
		result.CreatedAt = rt.CreatedAt.Time
	}
	return result, nil
}

func (r *refreshTokenRepo) Delete(ctx context.Context, token string) error {
	return r.q.DeleteRefreshToken(ctx, token)
}

func (r *refreshTokenRepo) DeleteAllForUser(ctx context.Context, userID string) error {
	pgID, err := parseUUID(userID)
	if err != nil {
		return err
	}
	return r.q.DeleteAllRefreshTokensForUser(ctx, pgID)
}

func (r *refreshTokenRepo) CountActiveForUser(ctx context.Context, userID string) (int64, error) {
	pgID, err := parseUUID(userID)
	if err != nil {
		return 0, err
	}
	return r.q.CountActiveRefreshTokensForUser(ctx, pgID)
}
