package jwt

import (
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/open-stash/sentinel/internal/config"
)

var (
	ErrInvalidToken = errors.New("jwt: invalid token")
	ErrExpiredToken = errors.New("jwt: token expired")
)

// KeyID labels the signing key in JWT headers + the JWKS, so resource servers
// (holocron's MCP) can match a token to the right public key.
const KeyID = "openstash-rs256-1"

// Claims is the payload embedded in every access token.
type Claims struct {
	Email string `json:"email"`
	Role  string `json:"role"`
	SID   string `json:"sid,omitempty"` // session id — links the access token to a revocable session
	jwt.RegisteredClaims
	// RegisteredClaims carries:
	//   Subject   (sub)  → user UUID
	//   ID        (jti)  → unique token ID, used for blacklisting on logout
	//   IssuedAt  (iat)
	//   ExpiresAt (exp)
}

// Signer issues and validates RS256 JWT access tokens.
// Create once at startup with NewSigner; safe for concurrent use.
type Signer struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	cfg        config.JWTConfig
}

// NewSigner loads RSA keys from the paths in cfg and returns a ready Signer.
func NewSigner(cfg config.JWTConfig) (*Signer, error) {
	privPEM, err := os.ReadFile(cfg.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("jwt: read private key %q: %w", cfg.PrivateKeyPath, err)
	}
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privPEM)
	if err != nil {
		return nil, fmt.Errorf("jwt: parse private key: %w", err)
	}

	pubPEM, err := os.ReadFile(cfg.PublicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("jwt: read public key %q: %w", cfg.PublicKeyPath, err)
	}
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(pubPEM)
	if err != nil {
		return nil, fmt.Errorf("jwt: parse public key: %w", err)
	}

	return &Signer{
		privateKey: privateKey,
		publicKey:  publicKey,
		cfg:        cfg,
	}, nil
}

// Sign creates and returns a signed RS256 access token for the given user.
// ttl controls expiry; pass cfg.JWT.AccessTokenTTL from the caller.
func (s *Signer) Sign(userID, email, role, sid string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := Claims{
		Email: email,
		Role:  role,
		SID:   sid,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			ID:        uuid.NewString(), // jti — blacklisted on logout
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", fmt.Errorf("jwt: sign: %w", err)
	}
	return signed, nil
}

// Verify parses and fully validates a token — signature, expiry, algorithm.
// Returns ErrExpiredToken if the token is past its exp claim.
// Returns ErrInvalidToken for any other failure.
func (s *Signer) Verify(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, s.keyFunc)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}
	return claims, nil
}

// ExtractJTI parses the token and returns its jti claim without checking expiry.
// Used during logout: the token may already be expired, but we still need its
// JTI to add to the Redis blacklist for its remaining TTL.
func (s *Signer) ExtractJTI(tokenStr string) (string, error) {
	token, err := jwt.ParseWithClaims(
		tokenStr,
		&Claims{},
		s.keyFunc,
		jwt.WithoutClaimsValidation(), // skip exp/nbf/iat checks
	)
	if err != nil {
		return "", ErrInvalidToken
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return "", ErrInvalidToken
	}
	return claims.ID, nil
}

// keyFunc validates the signing algorithm and returns the public key.
func (s *Signer) keyFunc(t *jwt.Token) (any, error) {
	if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
		return nil, fmt.Errorf("jwt: unexpected signing method %q", t.Header["alg"])
	}
	return s.publicKey, nil
}

// OAuthClaims is the payload of an OAuth 2.1 access token issued for the MCP server.
// `aud` (the resource indicator) + `iss` let the resource server validate the token is
// for it; `scope`/`client_id` record what was granted and to whom.
type OAuthClaims struct {
	Scope    string `json:"scope,omitempty"`
	ClientID string `json:"client_id,omitempty"`
	jwt.RegisteredClaims
}

// SignAccess issues an OAuth access token (RS256, same key as session tokens) bound to a
// user, the requesting client, and the target resource (audience). Used by the OAuth
// token endpoint; holocron's MCP verifies it via the JWKS below.
func (s *Signer) SignAccess(
	userID, clientID, scope, issuer string, audience []string, ttl time.Duration,
) (string, error) {
	now := time.Now()
	claims := OAuthClaims{
		Scope:    scope,
		ClientID: clientID,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			Issuer:    issuer,
			Audience:  audience,
			ID:        uuid.NewString(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = KeyID
	signed, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", fmt.Errorf("jwt: sign access: %w", err)
	}
	return signed, nil
}

// JWKS returns the public verification key as a JWK Set (RFC 7517), served at
// /.well-known/jwks.json so MCP resource servers can fetch it and verify signatures.
func (s *Signer) JWKS() map[string]any {
	eBytes := big.NewInt(int64(s.publicKey.E)).Bytes()
	return map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": KeyID,
				"n":   base64.RawURLEncoding.EncodeToString(s.publicKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(eBytes),
			},
		},
	}
}
