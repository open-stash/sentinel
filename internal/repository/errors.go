package repository

import "errors"

var (
	// ErrNotFound is returned when a requested record does not exist.
	ErrNotFound = errors.New("repository: record not found")

	// ErrDuplicate is returned when a unique constraint is violated (e.g. duplicate email).
	ErrDuplicate = errors.New("repository: duplicate record")
)
