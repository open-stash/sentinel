package password

import (
	"errors"
	"fmt"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

// cost is intentionally high (~250ms on modern hardware).
// Slowing down hash comparisons is the primary defense against brute-force attacks.
const cost = 12

var (
	ErrTooShort        = errors.New("password must be at least 8 characters")
	ErrMissingUppercase = errors.New("password must contain at least one uppercase letter")
	ErrMissingDigit    = errors.New("password must contain at least one digit")
)

// Hash returns a bcrypt hash of plain using cost 12.
func Hash(plain string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(plain), cost)
	if err != nil {
		return "", fmt.Errorf("password: hash: %w", err)
	}
	return string(hashed), nil
}

// Verify returns true if plain matches the stored bcrypt hash.
func Verify(plain, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil
}

// CheckStrength returns an error if plain does not meet minimum requirements:
// at least 8 characters, one uppercase letter, and one digit.
func CheckStrength(plain string) error {
	if len(plain) < 8 {
		return ErrTooShort
	}

	var hasUpper, hasDigit bool
	for _, ch := range plain {
		switch {
		case unicode.IsUpper(ch):
			hasUpper = true
		case unicode.IsDigit(ch):
			hasDigit = true
		}
		if hasUpper && hasDigit {
			break
		}
	}

	if !hasUpper {
		return ErrMissingUppercase
	}
	if !hasDigit {
		return ErrMissingDigit
	}
	return nil
}
