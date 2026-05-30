package service

import (
	"errors"
	"fmt"
	"time"
)

var (
	ErrEmailTaken         = errors.New("email already registered")
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrAccountLocked      = errors.New("account temporarily locked")
	ErrEmailNotVerified   = errors.New("email address not verified")
	ErrTOTPRequired       = errors.New("2FA code required")
	ErrInvalid2FA         = errors.New("invalid 2FA code")
	ErrInvalidToken       = errors.New("invalid or expired token")
	ErrTOTPAlreadyEnabled = errors.New("2FA is already enabled")
	ErrTOTPNotSetup       = errors.New("2FA setup not started — call /totp/setup first")
)

// RateLimitedError is returned when an IP has exceeded the login attempt budget.
// RetryAfter tells the caller how long to wait before trying again.
type RateLimitedError struct {
	RetryAfter time.Duration
}

func (e *RateLimitedError) Error() string {
	return fmt.Sprintf("too many login attempts, retry after %s", e.RetryAfter)
}

