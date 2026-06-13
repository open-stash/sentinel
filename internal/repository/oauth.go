package repository

import (
	"context"
	"time"
)

// OAuthClient is a dynamically-registered OAuth client (ChatGPT/Claude).
type OAuthClient struct {
	ClientID     string
	ClientName   string
	RedirectURIs []string
}

type CreateAuthCodeInput struct {
	CodeHash      string
	ClientID      string
	UserID        string
	RedirectURI   string
	CodeChallenge string
	Scope         string
	Resource      string
	ExpiresAt     time.Time
}

// AuthCode is a stored (single-use) authorization code's metadata.
type AuthCode struct {
	ClientID      string
	UserID        string
	RedirectURI   string
	CodeChallenge string
	Scope         string
	Resource      string
	ExpiresAt     time.Time
}

type CreateOAuthRefreshTokenInput struct {
	TokenHash string
	ClientID  string
	UserID    string
	Scope     string
	Resource  string
	ExpiresAt time.Time
}

// OAuthRefreshToken is a stored OAuth refresh token's metadata.
type OAuthRefreshToken struct {
	ClientID string
	UserID   string
	Scope    string
	Resource string
}

// OAuthRepository persists OAuth clients, authorization codes, and refresh tokens.
type OAuthRepository interface {
	CreateClient(ctx context.Context, clientID, name string, redirectURIs []string) (*OAuthClient, error)
	GetClient(ctx context.Context, clientID string) (*OAuthClient, error)
	CreateAuthCode(ctx context.Context, in CreateAuthCodeInput) error
	GetAuthCode(ctx context.Context, codeHash string) (*AuthCode, error)
	DeleteAuthCode(ctx context.Context, codeHash string) error
	CreateRefreshToken(ctx context.Context, in CreateOAuthRefreshTokenInput) error
	GetRefreshToken(ctx context.Context, tokenHash string) (*OAuthRefreshToken, error)
	RevokeRefreshToken(ctx context.Context, tokenHash string) error
}
