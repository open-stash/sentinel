package service

import "time"

type userRegisteredEvent struct {
	UserID    string    `json:"user_id"`
	Email     string    `json:"email"`
	OccuredAt time.Time `json:"occured_at"`
}

type userLoginEvent struct {
	UserID    string    `json:"user_id"`
	Email     string    `json:"email"`
	IPAddress string    `json:"ip_address"`
	OccuredAt time.Time `json:"occured_at"`
}

type userLogoutEvent struct {
	UserID    string    `json:"user_id"`
	OccuredAt time.Time `json:"occured_at"`
}

type userPasswordChangedEvent struct {
	UserID    string    `json:"user_id"`
	OccuredAt time.Time `json:"occured_at"`
}
