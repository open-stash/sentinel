package totp

import (
	"fmt"

	"github.com/pquerna/otp"
	totplib "github.com/pquerna/otp/totp"
)

// GenerateSecret creates a new TOTP key for the given user.
// Returns the base32 secret and the otpauth:// URL suitable for QR code generation.
func GenerateSecret(issuer, email string) (secret, otpAuthURL string, err error) {
	key, err := totplib.Generate(totplib.GenerateOpts{
		Issuer:      issuer,
		AccountName: email,
		Algorithm:   otp.AlgorithmSHA1,
		Digits:      otp.DigitsSix,
		Period:      30,
	})
	if err != nil {
		return "", "", fmt.Errorf("totp: generate secret: %w", err)
	}
	return key.Secret(), key.URL(), nil
}

// Verify returns true if passcode is a valid current TOTP code for secret.
func Verify(secret, passcode string) bool {
	return totplib.Validate(passcode, secret)
}
