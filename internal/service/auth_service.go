package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/open-stash/sentinel/internal/config"
	"github.com/open-stash/sentinel/internal/domain"
	"github.com/open-stash/sentinel/internal/repository"
	jwtpkg "github.com/open-stash/sentinel/pkg/jwt"
	"github.com/open-stash/sentinel/pkg/kafka"
	"github.com/open-stash/sentinel/pkg/password"
	totppkg "github.com/open-stash/sentinel/pkg/totp"
)

type AuthService struct {
	userRepo      repository.UserRepository
	refreshRepo   repository.RefreshTokenRepository
	blacklistRepo repository.BlacklistRepository
	rateLimitRepo repository.RateLimitRepository
	emailVerRepo  repository.EmailVerificationRepository
	passResetRepo repository.PasswordResetRepository
	jwtSigner     *jwtpkg.Signer
	producer      *kafka.Producer
	cfg           config.Config
}

func NewAuthService(
	userRepo repository.UserRepository,
	refreshRepo repository.RefreshTokenRepository,
	blacklistRepo repository.BlacklistRepository,
	rateLimitRepo repository.RateLimitRepository,
	emailVerRepo repository.EmailVerificationRepository,
	passResetRepo repository.PasswordResetRepository,
	jwtSigner *jwtpkg.Signer,
	producer *kafka.Producer,
	cfg config.Config,
) *AuthService {
	return &AuthService{
		userRepo:      userRepo,
		refreshRepo:   refreshRepo,
		blacklistRepo: blacklistRepo,
		rateLimitRepo: rateLimitRepo,
		emailVerRepo:  emailVerRepo,
		passResetRepo: passResetRepo,
		jwtSigner:     jwtSigner,
		producer:      producer,
		cfg:           cfg,
	}
}

// ─── Register ────────────────────────────────────────────────────────────────

func (s *AuthService) Register(ctx context.Context, email, rawPassword string) (*domain.User, string, error) {
	if err := password.CheckStrength(rawPassword); err != nil {
		return nil, "", err
	}

	hash, err := password.Hash(rawPassword)
	if err != nil {
		return nil, "", fmt.Errorf("register: hash password: %w", err)
	}

	user, err := s.userRepo.Create(ctx, email, hash, domain.RoleUser)
	if err != nil {
		if errors.Is(err, repository.ErrDuplicate) {
			return nil, "", ErrEmailTaken
		}
		return nil, "", fmt.Errorf("register: create user: %w", err)
	}

	verifyToken := secureToken()
	expiresAt := time.Now().Add(s.cfg.Auth.EmailVerifyTTL)
	if err := s.emailVerRepo.Create(ctx, verifyToken, user.ID, expiresAt); err != nil {
		slog.Error("register: create email verification token", "userID", user.ID, "error", err)
	}

	go func() {
		_ = s.producer.Enqueue(context.Background(), kafka.TopicUserRegistered, user.ID, userRegisteredEvent{
			UserID:    user.ID,
			Email:     user.Email,
			OccuredAt: time.Now(),
		})
	}()

	return user, verifyToken, nil
}

// ─── Login ───────────────────────────────────────────────────────────────────

func (s *AuthService) Login(ctx context.Context, in LoginInput) (*LoginOutput, error) {
	user, err := s.userRepo.GetByEmail(ctx, in.Email)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("login: get user: %w", err)
	}

	if user.IsLocked() {
		return nil, ErrAccountLocked
	}

	if !password.Verify(in.Password, user.PasswordHash) {
		newCount := user.FailedLogins + 1
		_ = s.userRepo.IncrementFailedLogins(ctx, user.ID)
		if int(newCount) >= s.cfg.Auth.RateLimitAttempts {
			_ = s.userRepo.LockUser(ctx, user.ID, time.Now().Add(s.cfg.Auth.RateLimitWindow))
		}
		return nil, ErrInvalidCredentials
	}

	if !user.IsEmailVerified {
		return nil, ErrEmailNotVerified
	}

	if user.TOTPEnabled {
		if in.TOTPCode == "" {
			return nil, ErrTOTPRequired
		}
		if !totppkg.Verify(user.TOTPSecret, in.TOTPCode) {
			return nil, ErrInvalid2FA
		}
	}

	_ = s.userRepo.ResetFailedLogins(ctx, user.ID)
	_ = s.rateLimitRepo.Reset(ctx, in.IPAddress)

	accessToken, err := s.jwtSigner.Sign(user.ID, user.Email, string(user.Role), s.cfg.JWT.AccessTokenTTL)
	if err != nil {
		return nil, fmt.Errorf("login: sign access token: %w", err)
	}

	refreshToken := secureToken()
	expiresAt := time.Now().Add(s.cfg.JWT.RefreshTokenTTL)
	if err := s.refreshRepo.Store(ctx, refreshToken, user.ID, in.IPAddress, in.UserAgent, expiresAt); err != nil {
		return nil, fmt.Errorf("login: store refresh token: %w", err)
	}

	go func() {
		_ = s.producer.Enqueue(context.Background(), kafka.TopicUserLogin, user.ID, userLoginEvent{
			UserID:    user.ID,
			Email:     user.Email,
			IPAddress: in.IPAddress,
			OccuredAt: time.Now(),
		})
	}()

	return &LoginOutput{
		Tokens: &domain.TokenPair{AccessToken: accessToken, RefreshToken: refreshToken},
		User:   user,
	}, nil
}

// ─── Logout ──────────────────────────────────────────────────────────────────

func (s *AuthService) Logout(ctx context.Context, accessToken, refreshToken, userID string) error {
	if jti, err := s.jwtSigner.ExtractJTI(accessToken); err == nil {
		_ = s.blacklistRepo.Add(ctx, jti, s.cfg.JWT.AccessTokenTTL)
	}

	if refreshToken != "" {
		_ = s.refreshRepo.Delete(ctx, refreshToken)
	}

	go func() {
		_ = s.producer.Enqueue(context.Background(), kafka.TopicUserLogout, userID, userLogoutEvent{
			UserID:    userID,
			OccuredAt: time.Now(),
		})
	}()

	return nil
}

// ─── Refresh ─────────────────────────────────────────────────────────────────

func (s *AuthService) Refresh(ctx context.Context, in RefreshInput) (*domain.TokenPair, error) {
	rt, err := s.refreshRepo.Get(ctx, in.RefreshToken)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrInvalidToken
		}
		return nil, fmt.Errorf("refresh: get token: %w", err)
	}

	if time.Now().After(rt.ExpiresAt) {
		_ = s.refreshRepo.Delete(ctx, in.RefreshToken)
		return nil, ErrInvalidToken
	}

	user, err := s.userRepo.GetByID(ctx, rt.UserID)
	if err != nil {
		return nil, fmt.Errorf("refresh: get user: %w", err)
	}

	// Rotate: delete old token before issuing new one
	_ = s.refreshRepo.Delete(ctx, in.RefreshToken)

	accessToken, err := s.jwtSigner.Sign(user.ID, user.Email, string(user.Role), s.cfg.JWT.AccessTokenTTL)
	if err != nil {
		return nil, fmt.Errorf("refresh: sign token: %w", err)
	}

	newRefresh := secureToken()
	expiresAt := time.Now().Add(s.cfg.JWT.RefreshTokenTTL)
	if err := s.refreshRepo.Store(ctx, newRefresh, user.ID, in.IPAddress, in.UserAgent, expiresAt); err != nil {
		return nil, fmt.Errorf("refresh: store new token: %w", err)
	}

	return &domain.TokenPair{AccessToken: accessToken, RefreshToken: newRefresh}, nil
}

// ─── Email Verification ───────────────────────────────────────────────────────

func (s *AuthService) VerifyEmail(ctx context.Context, token string) error {
	ev, err := s.emailVerRepo.Get(ctx, token)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrInvalidToken
		}
		return fmt.Errorf("verify email: get token: %w", err)
	}

	if ev.UsedAt != nil || time.Now().After(ev.ExpiresAt) {
		return ErrInvalidToken
	}

	if err := s.emailVerRepo.MarkUsed(ctx, token); err != nil {
		return fmt.Errorf("verify email: mark used: %w", err)
	}

	if err := s.userRepo.UpdateEmailVerified(ctx, ev.UserID); err != nil {
		return fmt.Errorf("verify email: update user: %w", err)
	}

	return nil
}

// ─── Password Reset ───────────────────────────────────────────────────────────

// ForgotPassword creates a reset token. Returns the token so the caller can
// send it via email (email sending is handled externally).
// Returns ("", nil) when the email is not registered — never reveals existence.
func (s *AuthService) ForgotPassword(ctx context.Context, email string) (string, error) {
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return "", nil
		}
		return "", fmt.Errorf("forgot password: get user: %w", err)
	}

	token := secureToken()
	expiresAt := time.Now().Add(s.cfg.Auth.PasswordResetTTL)
	if err := s.passResetRepo.Create(ctx, token, user.ID, expiresAt); err != nil {
		return "", fmt.Errorf("forgot password: create reset: %w", err)
	}

	return token, nil
}

func (s *AuthService) ResetPassword(ctx context.Context, token, newPassword string) error {
	if err := password.CheckStrength(newPassword); err != nil {
		return err
	}

	pr, err := s.passResetRepo.Get(ctx, token)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrInvalidToken
		}
		return fmt.Errorf("reset password: get token: %w", err)
	}

	if pr.UsedAt != nil || time.Now().After(pr.ExpiresAt) {
		return ErrInvalidToken
	}

	if err := s.passResetRepo.MarkUsed(ctx, token); err != nil {
		return fmt.Errorf("reset password: mark used: %w", err)
	}

	hash, err := password.Hash(newPassword)
	if err != nil {
		return fmt.Errorf("reset password: hash: %w", err)
	}

	if err := s.userRepo.UpdatePassword(ctx, pr.UserID, hash); err != nil {
		return fmt.Errorf("reset password: update: %w", err)
	}

	// Revoke all active sessions after password change
	_ = s.refreshRepo.DeleteAllForUser(ctx, pr.UserID)

	go func() {
		_ = s.producer.Enqueue(context.Background(), kafka.TopicUserPasswordChanged, pr.UserID, userPasswordChangedEvent{
			UserID:    pr.UserID,
			OccuredAt: time.Now(),
		})
	}()

	return nil
}

// ─── TOTP ─────────────────────────────────────────────────────────────────────

// SetupTOTP generates a new TOTP secret and persists it (disabled until verified).
// The caller should present OTPAuthURL as a QR code to the user.
func (s *AuthService) SetupTOTP(ctx context.Context, userID string) (*SetupTOTPOutput, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("setup totp: get user: %w", err)
	}

	if user.TOTPEnabled {
		return nil, ErrTOTPAlreadyEnabled
	}

	secret, otpURL, err := totppkg.GenerateSecret(s.cfg.TOTP.Issuer, user.Email)
	if err != nil {
		return nil, fmt.Errorf("setup totp: generate: %w", err)
	}

	if err := s.userRepo.UpdateTOTPSecret(ctx, userID, secret, false); err != nil {
		return nil, fmt.Errorf("setup totp: store secret: %w", err)
	}

	return &SetupTOTPOutput{Secret: secret, OTPAuthURL: otpURL}, nil
}

// EnableTOTP verifies the supplied code against the pending secret and, if valid,
// activates TOTP for the account.
func (s *AuthService) EnableTOTP(ctx context.Context, userID, code string) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("enable totp: get user: %w", err)
	}

	if user.TOTPEnabled {
		return ErrTOTPAlreadyEnabled
	}

	if user.TOTPSecret == "" {
		return ErrTOTPNotSetup
	}

	if !totppkg.Verify(user.TOTPSecret, code) {
		return ErrInvalid2FA
	}

	return s.userRepo.UpdateTOTPSecret(ctx, userID, user.TOTPSecret, true)
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func secureToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("auth service: failed to generate secure token: " + err.Error())
	}
	return hex.EncodeToString(b)
}
