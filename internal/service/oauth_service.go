package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/open-stash/sentinel/internal/config"
	"github.com/open-stash/sentinel/internal/repository"
	jwtpkg "github.com/open-stash/sentinel/pkg/jwt"
)

// OAuth errors map to the standard OAuth 2.0 error codes the handler returns.
var (
	ErrOAuthInvalidClient   = errors.New("oauth: invalid client")
	ErrOAuthInvalidRedirect = errors.New("oauth: invalid redirect_uri")
	ErrOAuthInvalidRequest  = errors.New("oauth: invalid request")
	ErrOAuthInvalidGrant    = errors.New("oauth: invalid grant")
)

// TokenResult is what the token endpoint returns to the client.
type TokenResult struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int
	Scope        string
}

type OAuthService struct {
	repo   repository.OAuthRepository
	signer *jwtpkg.Signer
	cfg    config.OAuthConfig
}

func NewOAuthService(repo repository.OAuthRepository, signer *jwtpkg.Signer, cfg config.OAuthConfig) *OAuthService {
	return &OAuthService{repo: repo, signer: signer, cfg: cfg}
}

// RegisterClient handles Dynamic Client Registration (RFC 7591). ChatGPT/Claude call
// this on first connect; we issue a public client_id (PKCE, no secret).
func (s *OAuthService) RegisterClient(
	ctx context.Context, name string, redirectURIs []string,
) (*repository.OAuthClient, error) {
	if len(redirectURIs) == 0 {
		return nil, ErrOAuthInvalidRequest
	}
	clientID := "osc_" + randToken()
	return s.repo.CreateClient(ctx, clientID, name, redirectURIs)
}

// IssueCode is called (server-side, by the holonet consent page) AFTER the user has
// authenticated and approved. It validates the client + redirect + PKCE challenge and
// mints a single-use authorization code.
func (s *OAuthService) IssueCode(
	ctx context.Context, userID, clientID, redirectURI, codeChallenge, scope, resource string,
) (string, error) {
	client, err := s.repo.GetClient(ctx, clientID)
	if err != nil {
		return "", ErrOAuthInvalidClient
	}
	if !contains(client.RedirectURIs, redirectURI) {
		return "", ErrOAuthInvalidRedirect
	}
	if codeChallenge == "" {
		return "", ErrOAuthInvalidRequest // PKCE is mandatory
	}
	code := randToken()
	err = s.repo.CreateAuthCode(ctx, repository.CreateAuthCodeInput{
		CodeHash:      sha256hex(code),
		ClientID:      clientID,
		UserID:        userID,
		RedirectURI:   redirectURI,
		CodeChallenge: codeChallenge,
		Scope:         scope,
		Resource:      resource,
		ExpiresAt:     time.Now().Add(s.cfg.CodeTTL),
	})
	if err != nil {
		return "", err
	}
	return code, nil
}

// ExchangeCode is the authorization_code grant: validate the code + PKCE verifier, then
// mint tokens. The code is single-use (deleted immediately).
func (s *OAuthService) ExchangeCode(
	ctx context.Context, code, codeVerifier, redirectURI, clientID string,
) (*TokenResult, error) {
	hash := sha256hex(code)
	ac, err := s.repo.GetAuthCode(ctx, hash)
	if err != nil {
		return nil, ErrOAuthInvalidGrant
	}
	_ = s.repo.DeleteAuthCode(ctx, hash) // single use, even on failure below
	if time.Now().After(ac.ExpiresAt) || ac.ClientID != clientID || ac.RedirectURI != redirectURI {
		return nil, ErrOAuthInvalidGrant
	}
	if !verifyPKCE(codeVerifier, ac.CodeChallenge) {
		return nil, ErrOAuthInvalidGrant
	}
	return s.mintTokens(ctx, ac.UserID, ac.ClientID, ac.Scope, ac.Resource)
}

// Refresh is the refresh_token grant (with rotation: the old token is revoked).
func (s *OAuthService) Refresh(ctx context.Context, refreshToken, clientID string) (*TokenResult, error) {
	hash := sha256hex(refreshToken)
	rt, err := s.repo.GetRefreshToken(ctx, hash)
	if err != nil {
		return nil, ErrOAuthInvalidGrant
	}
	if rt.ClientID != clientID {
		return nil, ErrOAuthInvalidGrant
	}
	_ = s.repo.RevokeRefreshToken(ctx, hash) // rotate
	return s.mintTokens(ctx, rt.UserID, rt.ClientID, rt.Scope, rt.Resource)
}

func (s *OAuthService) mintTokens(
	ctx context.Context, userID, clientID, scope, resource string,
) (*TokenResult, error) {
	aud := resource
	if aud == "" {
		aud = s.cfg.ResourceURL
	}
	access, err := s.signer.SignAccess(userID, clientID, scope, s.cfg.Issuer, []string{aud}, s.cfg.AccessTokenTTL)
	if err != nil {
		return nil, fmt.Errorf("oauth: sign access: %w", err)
	}
	refresh := randToken()
	if err := s.repo.CreateRefreshToken(ctx, repository.CreateOAuthRefreshTokenInput{
		TokenHash: sha256hex(refresh),
		ClientID:  clientID,
		UserID:    userID,
		Scope:     scope,
		Resource:  resource,
		ExpiresAt: time.Now().Add(s.cfg.RefreshTTL),
	}); err != nil {
		return nil, err
	}
	return &TokenResult{
		AccessToken:  access,
		RefreshToken: refresh,
		ExpiresIn:    int(s.cfg.AccessTokenTTL.Seconds()),
		Scope:        scope,
	}, nil
}

// Metadata is the OAuth 2.0 Authorization Server Metadata document (RFC 8414).
func (s *OAuthService) Metadata() map[string]any {
	return map[string]any{
		"issuer":                                s.cfg.Issuer,
		"authorization_endpoint":                s.cfg.ConsentURL,
		"token_endpoint":                        s.cfg.Issuer + "/oauth/token",
		"registration_endpoint":                 s.cfg.Issuer + "/oauth/register",
		"jwks_uri":                              s.cfg.Issuer + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"scopes_supported":                      []string{"memory"},
	}
}

// JWKS exposes the public verification key set.
func (s *OAuthService) JWKS() map[string]any { return s.signer.JWKS() }

// Connection is an app the user has connected to their memory (for the settings view).
type Connection struct {
	ClientID     string
	Name         string
	ConnectedAt  time.Time
	LastActiveAt time.Time
}

// ListConnections returns the apps (ChatGPT/Claude/…) with a live OAuth grant.
func (s *OAuthService) ListConnections(ctx context.Context, userID string) ([]Connection, error) {
	rows, err := s.repo.ListConnections(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]Connection, 0, len(rows))
	for _, r := range rows {
		out = append(out, Connection{
			ClientID:     r.ClientID,
			Name:         friendlyClientName(r.ClientName, r.RedirectURIs),
			ConnectedAt:  r.ConnectedAt,
			LastActiveAt: r.LastTokenAt,
		})
	}
	return out, nil
}

// RevokeConnection disconnects an app (revokes its refresh tokens; current access token
// keeps working until it expires, ~1h).
func (s *OAuthService) RevokeConnection(ctx context.Context, userID, clientID string) error {
	return s.repo.RevokeConnections(ctx, userID, clientID)
}

// friendlyClientName turns a DCR client into a human label, inferring from the redirect
// URI host since DCR client_name is often generic/empty.
func friendlyClientName(name string, redirects []string) string {
	for _, r := range redirects {
		u, err := url.Parse(r)
		if err != nil {
			continue
		}
		h := strings.ToLower(u.Hostname())
		switch {
		case strings.Contains(h, "chatgpt.com") || strings.Contains(h, "openai.com"):
			return "ChatGPT"
		case strings.Contains(h, "claude.ai") || strings.Contains(h, "anthropic"):
			return "Claude"
		case strings.Contains(h, "cursor"):
			return "Cursor"
		case h == "localhost" || h == "127.0.0.1":
			return "Local (Claude Code / Cursor)"
		}
	}
	if strings.TrimSpace(name) != "" {
		return name
	}
	return "Connected app"
}

// ── helpers ────────────────────────────────────────────────────────────────

func randToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// verifyPKCE checks an S256 code_verifier against the stored code_challenge.
func verifyPKCE(verifier, challenge string) bool {
	if verifier == "" || challenge == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
