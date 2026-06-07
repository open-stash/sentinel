package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/open-stash/sentinel/internal/domain"
	"github.com/open-stash/sentinel/internal/repository"
	db "github.com/open-stash/sentinel/pkg/db"
)

type sessionRepo struct {
	q *db.Queries
}

func NewSessionRepository(q *db.Queries) repository.SessionRepository {
	return &sessionRepo{q: q}
}

func (r *sessionRepo) Create(ctx context.Context, in repository.CreateSessionInput) (*domain.Session, error) {
	uid, err := parseUUID(in.UserID)
	if err != nil {
		return nil, err
	}
	s, err := r.q.CreateSession(ctx, db.CreateSessionParams{
		UserID:    uid,
		TokenHash: in.TokenHash,
		UserAgent: pgText(in.UserAgent),
		Device:    pgText(in.Device),
		Browser:   pgText(in.Browser),
		Os:        pgText(in.OS),
		ExpiresAt: pgtype.Timestamptz{Time: in.ExpiresAt, Valid: true},
	})
	if err != nil {
		return nil, fmt.Errorf("session repo: create: %w", err)
	}
	return toDomainSession(s), nil
}

func (r *sessionRepo) GetByTokenHash(ctx context.Context, tokenHash string) (*domain.Session, error) {
	s, err := r.q.GetSessionByTokenHash(ctx, tokenHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("session repo: get by token: %w", err)
	}
	return toDomainSession(s), nil
}

func (r *sessionRepo) GetByID(ctx context.Context, id string) (*domain.Session, error) {
	sid, err := parseUUID(id)
	if err != nil {
		return nil, err
	}
	s, err := r.q.GetSessionByID(ctx, sid)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("session repo: get by id: %w", err)
	}
	return toDomainSession(s), nil
}

func (r *sessionRepo) ListActiveByUser(ctx context.Context, userID string) ([]domain.Session, error) {
	uid, err := parseUUID(userID)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ListActiveSessionsByUser(ctx, uid)
	if err != nil {
		return nil, fmt.Errorf("session repo: list: %w", err)
	}
	out := make([]domain.Session, 0, len(rows))
	for _, s := range rows {
		out = append(out, *toDomainSession(s))
	}
	return out, nil
}

func (r *sessionRepo) Touch(ctx context.Context, id string) error {
	sid, err := parseUUID(id)
	if err != nil {
		return err
	}
	return r.q.TouchSession(ctx, sid)
}

func (r *sessionRepo) Revoke(ctx context.Context, id, userID string) error {
	sid, err := parseUUID(id)
	if err != nil {
		return err
	}
	uid, err := parseUUID(userID)
	if err != nil {
		return err
	}
	return r.q.RevokeSession(ctx, db.RevokeSessionParams{ID: sid, UserID: uid})
}

func (r *sessionRepo) RevokeByTokenHash(ctx context.Context, tokenHash string) error {
	return r.q.RevokeSessionByTokenHash(ctx, tokenHash)
}

func (r *sessionRepo) RevokeOthers(ctx context.Context, userID, keepID string) error {
	uid, err := parseUUID(userID)
	if err != nil {
		return err
	}
	sid, err := parseUUID(keepID)
	if err != nil {
		return err
	}
	return r.q.RevokeOtherSessions(ctx, db.RevokeOtherSessionsParams{UserID: uid, ID: sid})
}

func (r *sessionRepo) RevokeAllForUser(ctx context.Context, userID string) error {
	uid, err := parseUUID(userID)
	if err != nil {
		return err
	}
	return r.q.RevokeAllUserSessions(ctx, uid)
}

func (r *sessionRepo) DeleteExpired(ctx context.Context) error {
	return r.q.DeleteExpiredSessions(ctx)
}

func pgText(s string) pgtype.Text {
	return pgtype.Text{String: s, Valid: s != ""}
}

func toDomainSession(s db.Session) *domain.Session {
	ds := &domain.Session{
		ID:        uuid.UUID(s.ID.Bytes).String(),
		UserID:    uuid.UUID(s.UserID.Bytes).String(),
		UserAgent: s.UserAgent.String,
		Device:    s.Device.String,
		Browser:   s.Browser.String,
		OS:        s.Os.String,
	}
	if s.CreatedAt.Valid {
		ds.CreatedAt = s.CreatedAt.Time
	}
	if s.LastSeenAt.Valid {
		ds.LastSeenAt = s.LastSeenAt.Time
	}
	if s.ExpiresAt.Valid {
		ds.ExpiresAt = s.ExpiresAt.Time
	}
	if s.RevokedAt.Valid {
		t := s.RevokedAt.Time
		ds.RevokedAt = &t
	}
	return ds
}
