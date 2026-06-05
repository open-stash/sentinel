package domain

import "time"

type Role string

const (
	RoleUser  Role = "user"
	RoleAdmin Role = "admin"
)

type User struct {
	ID              string
	Name            string
	Email           string
	PasswordHash    string
	Role            Role
	IsEmailVerified bool
	TOTPSecret      string
	TOTPEnabled     bool
	FailedLogins    int32
	LockedUntil     *time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

func (u *User) IsLocked() bool {
	return u.LockedUntil != nil && time.Now().Before(*u.LockedUntil)
}
