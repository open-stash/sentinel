package domain

import "time"

// APIKey is a long-lived credential a user issues for external MCP clients to reach
// the memory layer. Only the hash is persisted; the plaintext is shown once at creation.
type APIKey struct {
	ID         string
	UserID     string
	Name       string
	Prefix     string // e.g. "osk_AbCdEf" — safe to display
	LastUsedAt *time.Time
	CreatedAt  time.Time
}
