package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/open-stash/sentinel/internal/domain"
	"github.com/open-stash/sentinel/internal/repository"
	db "github.com/open-stash/sentinel/pkg/db"
)

const pgErrUniqueViolation = "23505"

type userRepo struct {
	q *db.Queries
}

func NewUserRepository(q *db.Queries) repository.UserRepository {
	return &userRepo{q: q}
}

func (r *userRepo) Create(ctx context.Context, name, email, passwordHash string, role domain.Role) (*domain.User, error) {
	u, err := r.q.CreateUser(ctx, db.CreateUserParams{
		Name:         name,
		Email:        email,
		PasswordHash: passwordHash,
		Role:         string(role),
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgErrUniqueViolation {
			return nil, repository.ErrDuplicate
		}
		return nil, fmt.Errorf("user repo: create: %w", err)
	}
	return toDomainUser(u), nil
}

func (r *userRepo) GetByID(ctx context.Context, id string) (*domain.User, error) {
	pgID, err := parseUUID(id)
	if err != nil {
		return nil, err
	}
	u, err := r.q.GetUserByID(ctx, pgID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("user repo: get by id: %w", err)
	}
	return toDomainUser(u), nil
}

func (r *userRepo) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	u, err := r.q.GetUserByEmail(ctx, email)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("user repo: get by email: %w", err)
	}
	return toDomainUser(u), nil
}

func (r *userRepo) UpdateEmailVerified(ctx context.Context, id string) error {
	pgID, err := parseUUID(id)
	if err != nil {
		return err
	}
	return r.q.UpdateEmailVerified(ctx, pgID)
}

func (r *userRepo) UpdatePassword(ctx context.Context, id, passwordHash string) error {
	pgID, err := parseUUID(id)
	if err != nil {
		return err
	}
	return r.q.UpdatePassword(ctx, db.UpdatePasswordParams{ID: pgID, PasswordHash: passwordHash})
}

func (r *userRepo) UpdateTOTPSecret(ctx context.Context, id, secret string, enabled bool) error {
	pgID, err := parseUUID(id)
	if err != nil {
		return err
	}
	return r.q.UpdateTOTPSecret(ctx, db.UpdateTOTPSecretParams{
		ID:          pgID,
		TotpSecret:  pgtype.Text{String: secret, Valid: secret != ""},
		TotpEnabled: enabled,
	})
}

func (r *userRepo) IncrementFailedLogins(ctx context.Context, id string) error {
	pgID, err := parseUUID(id)
	if err != nil {
		return err
	}
	return r.q.IncrementFailedLogins(ctx, pgID)
}

func (r *userRepo) LockUser(ctx context.Context, id string, until time.Time) error {
	pgID, err := parseUUID(id)
	if err != nil {
		return err
	}
	return r.q.LockUser(ctx, db.LockUserParams{
		ID:          pgID,
		LockedUntil: pgtype.Timestamptz{Time: until, Valid: true},
	})
}

func (r *userRepo) ResetFailedLogins(ctx context.Context, id string) error {
	pgID, err := parseUUID(id)
	if err != nil {
		return err
	}
	return r.q.ResetFailedLogins(ctx, pgID)
}

func parseUUID(id string) (pgtype.UUID, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("invalid uuid %q: %w", id, err)
	}
	return pgtype.UUID{Bytes: uid, Valid: true}, nil
}

func toDomainUser(u db.User) *domain.User {
	du := &domain.User{
		ID:              uuid.UUID(u.ID.Bytes).String(),
		Name:            u.Name,
		Email:           u.Email,
		PasswordHash:    u.PasswordHash,
		Role:            domain.Role(u.Role),
		IsEmailVerified: u.IsEmailVerified,
		TOTPEnabled:     u.TotpEnabled,
		FailedLogins:    u.FailedLogins,
	}
	if u.TotpSecret.Valid {
		du.TOTPSecret = u.TotpSecret.String
	}
	if u.LockedUntil.Valid {
		t := u.LockedUntil.Time
		du.LockedUntil = &t
	}
	if u.CreatedAt.Valid {
		du.CreatedAt = u.CreatedAt.Time
	}
	if u.UpdatedAt.Valid {
		du.UpdatedAt = u.UpdatedAt.Time
	}
	return du
}
