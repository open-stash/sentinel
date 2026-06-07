package service

import "github.com/open-stash/sentinel/internal/domain"

type LoginInput struct {
	Email     string
	Password  string
	TOTPCode  string
	UserAgent string
}

type LoginOutput struct {
	Tokens *domain.TokenPair
	User   *domain.User
}

type RefreshInput struct {
	RefreshToken string
	UserAgent    string
}

type SetupTOTPOutput struct {
	Secret     string
	OTPAuthURL string
}
