package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/open-stash/sentinel/internal/repository"
	db "github.com/open-stash/sentinel/pkg/db"
)

type oauthRepo struct {
	q *db.Queries
}

func NewOAuthRepository(q *db.Queries) repository.OAuthRepository {
	return &oauthRepo{q: q}
}

func (r *oauthRepo) CreateClient(
	ctx context.Context, clientID, name string, redirectURIs []string,
) (*repository.OAuthClient, error) {
	c, err := r.q.CreateOAuthClient(ctx, db.CreateOAuthClientParams{
		ClientID:     clientID,
		ClientName:   name,
		RedirectUris: redirectURIs,
	})
	if err != nil {
		return nil, fmt.Errorf("oauth repo: create client: %w", err)
	}
	return &repository.OAuthClient{
		ClientID: c.ClientID, ClientName: c.ClientName, RedirectURIs: c.RedirectUris,
	}, nil
}

func (r *oauthRepo) GetClient(ctx context.Context, clientID string) (*repository.OAuthClient, error) {
	c, err := r.q.GetOAuthClient(ctx, clientID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("oauth repo: get client: %w", err)
	}
	return &repository.OAuthClient{
		ClientID: c.ClientID, ClientName: c.ClientName, RedirectURIs: c.RedirectUris,
	}, nil
}

func (r *oauthRepo) CreateAuthCode(ctx context.Context, in repository.CreateAuthCodeInput) error {
	uid, err := parseUUID(in.UserID)
	if err != nil {
		return err
	}
	return r.q.CreateAuthCode(ctx, db.CreateAuthCodeParams{
		CodeHash:      in.CodeHash,
		ClientID:      in.ClientID,
		UserID:        uid,
		RedirectUri:   in.RedirectURI,
		CodeChallenge: in.CodeChallenge,
		Scope:         in.Scope,
		Resource:      in.Resource,
		ExpiresAt:     pgtype.Timestamptz{Time: in.ExpiresAt, Valid: true},
	})
}

func (r *oauthRepo) GetAuthCode(ctx context.Context, codeHash string) (*repository.AuthCode, error) {
	c, err := r.q.GetAuthCode(ctx, codeHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("oauth repo: get auth code: %w", err)
	}
	return &repository.AuthCode{
		ClientID:      c.ClientID,
		UserID:        uuid.UUID(c.UserID.Bytes).String(),
		RedirectURI:   c.RedirectUri,
		CodeChallenge: c.CodeChallenge,
		Scope:         c.Scope,
		Resource:      c.Resource,
		ExpiresAt:     c.ExpiresAt.Time,
	}, nil
}

func (r *oauthRepo) DeleteAuthCode(ctx context.Context, codeHash string) error {
	return r.q.DeleteAuthCode(ctx, codeHash)
}

func (r *oauthRepo) CreateRefreshToken(ctx context.Context, in repository.CreateOAuthRefreshTokenInput) error {
	uid, err := parseUUID(in.UserID)
	if err != nil {
		return err
	}
	return r.q.CreateOAuthRefreshToken(ctx, db.CreateOAuthRefreshTokenParams{
		TokenHash: in.TokenHash,
		ClientID:  in.ClientID,
		UserID:    uid,
		Scope:     in.Scope,
		Resource:  in.Resource,
		ExpiresAt: pgtype.Timestamptz{Time: in.ExpiresAt, Valid: true},
	})
}

func (r *oauthRepo) GetRefreshToken(ctx context.Context, tokenHash string) (*repository.OAuthRefreshToken, error) {
	t, err := r.q.GetOAuthRefreshToken(ctx, tokenHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("oauth repo: get refresh: %w", err)
	}
	return &repository.OAuthRefreshToken{
		ClientID: t.ClientID,
		UserID:   uuid.UUID(t.UserID.Bytes).String(),
		Scope:    t.Scope,
		Resource: t.Resource,
	}, nil
}

func (r *oauthRepo) RevokeRefreshToken(ctx context.Context, tokenHash string) error {
	return r.q.RevokeOAuthRefreshToken(ctx, tokenHash)
}
