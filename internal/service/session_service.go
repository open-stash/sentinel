package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/open-stash/sentinel/internal/domain"
	"github.com/open-stash/sentinel/internal/repository"
)

const (
	sessionTokenBytes = 32               // 256-bit opaque token
	touchInterval     = 60 * time.Second // throttle last_seen writes
)

// SessionMeta is the per-session context captured at creation (device only).
type SessionMeta struct {
	UserAgent string
	Device    string
	Browser   string
	OS        string
}

// SessionService owns the lifecycle of server-side sessions. The opaque token is
// returned to the caller exactly once (for the cookie); only its hash is stored.
type SessionService struct {
	repo repository.SessionRepository
	ttl  time.Duration
}

func NewSessionService(repo repository.SessionRepository, ttl time.Duration) *SessionService {
	return &SessionService{repo: repo, ttl: ttl}
}

// Create issues a new session and returns the RAW token (cookie value) + the record.
func (s *SessionService) Create(ctx context.Context, userID string, meta SessionMeta) (string, *domain.Session, error) {
	raw, err := generateSessionToken()
	if err != nil {
		return "", nil, err
	}
	sess, err := s.repo.Create(ctx, repository.CreateSessionInput{
		UserID:    userID,
		TokenHash: hashSessionToken(raw),
		UserAgent: meta.UserAgent,
		Device:    meta.Device,
		Browser:   meta.Browser,
		OS:        meta.OS,
		ExpiresAt: time.Now().Add(s.ttl),
	})
	if err != nil {
		return "", nil, err
	}
	return raw, sess, nil
}

// Validate resolves a raw token to an active session and refreshes last_seen
// (throttled). Returns ErrInvalidToken for missing/expired/revoked sessions.
func (s *SessionService) Validate(ctx context.Context, rawToken string) (*domain.Session, error) {
	if rawToken == "" {
		return nil, ErrInvalidToken
	}
	sess, err := s.repo.GetByTokenHash(ctx, hashSessionToken(rawToken))
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrInvalidToken
		}
		return nil, fmt.Errorf("session validate: %w", err)
	}
	if !sess.Active() {
		return nil, ErrInvalidToken
	}
	if time.Since(sess.LastSeenAt) > touchInterval {
		_ = s.repo.Touch(ctx, sess.ID)
	}
	return sess, nil
}

// RevokeByToken revokes the session matching a raw cookie token (logout).
func (s *SessionService) RevokeByToken(ctx context.Context, rawToken string) error {
	if rawToken == "" {
		return nil
	}
	return s.repo.RevokeByTokenHash(ctx, hashSessionToken(rawToken))
}

// Revoke revokes a specific session owned by userID (manage-devices).
func (s *SessionService) Revoke(ctx context.Context, sessionID, userID string) error {
	return s.repo.Revoke(ctx, sessionID, userID)
}

// RevokeOthers revokes every session of userID except keepSessionID ("log out everywhere else").
func (s *SessionService) RevokeOthers(ctx context.Context, userID, keepSessionID string) error {
	return s.repo.RevokeOthers(ctx, userID, keepSessionID)
}

// RevokeAllForUser revokes every active session of userID (e.g. on password change).
func (s *SessionService) RevokeAllForUser(ctx context.Context, userID string) error {
	return s.repo.RevokeAllForUser(ctx, userID)
}

// List returns the user's active sessions for the devices UI.
func (s *SessionService) List(ctx context.Context, userID string) ([]domain.Session, error) {
	return s.repo.ListActiveByUser(ctx, userID)
}

// Get returns a session by id (used by token introspection to check revocation).
func (s *SessionService) Get(ctx context.Context, id string) (*domain.Session, error) {
	return s.repo.GetByID(ctx, id)
}

func generateSessionToken() (string, error) {
	b := make([]byte, sessionTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate session token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func hashSessionToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
