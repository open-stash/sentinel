package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/open-stash/sentinel/internal/domain"
	"github.com/open-stash/sentinel/internal/repository"
)

const apiKeyPrefix = "osk_" // open-stash key

type APIKeyService struct {
	repo repository.APIKeyRepository
}

func NewAPIKeyService(repo repository.APIKeyRepository) *APIKeyService {
	return &APIKeyService{repo: repo}
}

// Create mints a new key, stores only its hash, and returns the plaintext ONCE.
func (s *APIKeyService) Create(ctx context.Context, userID, name string) (plaintext string, key *domain.APIKey, err error) {
	raw, err := generateAPIKey()
	if err != nil {
		return "", nil, err
	}
	hash := hashAPIKey(raw)
	prefix := raw
	if len(raw) > 11 {
		prefix = raw[:11] // "osk_" + 7 chars
	}
	key, err = s.repo.Create(ctx, repository.CreateAPIKeyInput{
		UserID:  userID,
		Name:    name,
		KeyHash: hash,
		Prefix:  prefix,
	})
	if err != nil {
		return "", nil, err
	}
	return raw, key, nil
}

// Verify maps a presented plaintext key to its owner, or returns ErrNotFound.
func (s *APIKeyService) Verify(ctx context.Context, rawKey string) (userID string, err error) {
	k, err := s.repo.GetByHash(ctx, hashAPIKey(rawKey))
	if err != nil {
		return "", err
	}
	_ = s.repo.Touch(ctx, k.ID) // best-effort last_used
	return k.UserID, nil
}

func (s *APIKeyService) List(ctx context.Context, userID string) ([]domain.APIKey, error) {
	return s.repo.ListByUser(ctx, userID)
}

func (s *APIKeyService) Revoke(ctx context.Context, id, userID string) error {
	return s.repo.Revoke(ctx, id, userID)
}

func generateAPIKey() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("apikey: rand: %w", err)
	}
	return apiKeyPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// API keys are high-entropy random tokens, so a fast sha256 (indexable) is the right
// hash — unlike passwords, which need a slow KDF.
func hashAPIKey(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
