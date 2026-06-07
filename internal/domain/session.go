package domain

import "time"

// Session is a server-side authentication session. The opaque token itself is
// never stored or exposed — only its SHA-256 hash lives in the DB/cache.
type Session struct {
	ID         string
	UserID     string
	UserAgent  string
	Device     string
	Browser    string
	OS         string
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
	RevokedAt  *time.Time
}

// Active reports whether the session is currently usable.
func (s *Session) Active() bool {
	return s.RevokedAt == nil && time.Now().Before(s.ExpiresAt)
}
