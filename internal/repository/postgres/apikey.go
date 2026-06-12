package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/open-stash/sentinel/internal/domain"
	"github.com/open-stash/sentinel/internal/repository"
	db "github.com/open-stash/sentinel/pkg/db"
)

type apiKeyRepo struct {
	q *db.Queries
}

func NewAPIKeyRepository(q *db.Queries) repository.APIKeyRepository {
	return &apiKeyRepo{q: q}
}

func (r *apiKeyRepo) Create(ctx context.Context, in repository.CreateAPIKeyInput) (*domain.APIKey, error) {
	uid, err := parseUUID(in.UserID)
	if err != nil {
		return nil, err
	}
	k, err := r.q.CreateAPIKey(ctx, db.CreateAPIKeyParams{
		UserID:  uid,
		Name:    in.Name,
		KeyHash: in.KeyHash,
		Prefix:  in.Prefix,
	})
	if err != nil {
		return nil, fmt.Errorf("apikey repo: create: %w", err)
	}
	return toDomainAPIKey(k), nil
}

func (r *apiKeyRepo) GetByHash(ctx context.Context, keyHash string) (*domain.APIKey, error) {
	k, err := r.q.GetAPIKeyByHash(ctx, keyHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("apikey repo: get by hash: %w", err)
	}
	return toDomainAPIKey(k), nil
}

func (r *apiKeyRepo) ListByUser(ctx context.Context, userID string) ([]domain.APIKey, error) {
	uid, err := parseUUID(userID)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListAPIKeysByUser(ctx, uid)
	if err != nil {
		return nil, fmt.Errorf("apikey repo: list: %w", err)
	}
	out := make([]domain.APIKey, 0, len(rows))
	for _, k := range rows {
		out = append(out, *toDomainAPIKey(k))
	}
	return out, nil
}

func (r *apiKeyRepo) Revoke(ctx context.Context, id, userID string) error {
	kid, err := parseUUID(id)
	if err != nil {
		return err
	}
	uid, err := parseUUID(userID)
	if err != nil {
		return err
	}
	return r.q.RevokeAPIKey(ctx, db.RevokeAPIKeyParams{ID: kid, UserID: uid})
}

func (r *apiKeyRepo) Touch(ctx context.Context, id string) error {
	kid, err := parseUUID(id)
	if err != nil {
		return err
	}
	return r.q.TouchAPIKey(ctx, kid)
}

func toDomainAPIKey(k db.ApiKey) *domain.APIKey {
	d := &domain.APIKey{
		ID:     uuid.UUID(k.ID.Bytes).String(),
		UserID: uuid.UUID(k.UserID.Bytes).String(),
		Name:   k.Name,
		Prefix: k.Prefix,
	}
	if k.CreatedAt.Valid {
		d.CreatedAt = k.CreatedAt.Time
	}
	if k.LastUsedAt.Valid {
		t := k.LastUsedAt.Time
		d.LastUsedAt = &t
	}
	return d
}
