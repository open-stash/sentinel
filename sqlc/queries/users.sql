-- name: CreateUser :one
INSERT INTO users (email, password_hash, role)
VALUES ($1, $2, $3)
RETURNING *;

-- name: GetUserByID :one
SELECT * FROM users
WHERE id = $1;

-- name: GetUserByEmail :one
SELECT * FROM users
WHERE email = $1;

-- name: UpdateEmailVerified :exec
UPDATE users
SET is_email_verified = true,
    updated_at = now()
WHERE id = $1;

-- name: UpdatePassword :exec
UPDATE users
SET password_hash = $2,
    updated_at    = now()
WHERE id = $1;

-- name: UpdateTOTPSecret :exec
UPDATE users
SET totp_secret  = $2,
    totp_enabled = $3,
    updated_at   = now()
WHERE id = $1;

-- name: IncrementFailedLogins :exec
UPDATE users
SET failed_logins = failed_logins + 1,
    updated_at    = now()
WHERE id = $1;

-- name: LockUser :exec
UPDATE users
SET locked_until = $2,
    updated_at   = now()
WHERE id = $1;

-- name: ResetFailedLogins :exec
UPDATE users
SET failed_logins = 0,
    locked_until  = NULL,
    updated_at    = now()
WHERE id = $1;
