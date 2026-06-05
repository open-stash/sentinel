package service

// Event type identifiers and payload shapes published to beacon (the email
// worker). These must match beacon's domain.NotificationEvent contract:
// an envelope {type, payload} where payload matches the type below.
const (
	eventUserWelcome         = "user.welcome"
	eventUserPasswordChanged = "user.password_changed"
)

// welcomePayload → user.welcome. Sent on registration; carries the email
// verification link so the welcome email doubles as the verify email.
type welcomePayload struct {
	Name      string `json:"name"`
	Email     string `json:"email"`
	VerifyURL string `json:"verify_url"`
}

// passwordChangedPayload → user.password_changed.
type passwordChangedPayload struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}
