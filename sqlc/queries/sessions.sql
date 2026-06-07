-- name: CreateSession :one
INSERT INTO sessions (
    user_id, token_hash, user_agent, device, browser, os, expires_at
) VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: GetSessionByTokenHash :one
SELECT * FROM sessions
WHERE token_hash = $1;

-- name: GetSessionByID :one
SELECT * FROM sessions
WHERE id = $1;

-- name: ListActiveSessionsByUser :many
SELECT * FROM sessions
WHERE user_id = $1
  AND revoked_at IS NULL
  AND expires_at > now()
ORDER BY last_seen_at DESC;

-- name: TouchSession :exec
UPDATE sessions
SET last_seen_at = now()
WHERE id = $1;

-- name: RevokeSession :exec
UPDATE sessions
SET revoked_at = now()
WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL;

-- name: RevokeSessionByTokenHash :exec
UPDATE sessions
SET revoked_at = now()
WHERE token_hash = $1;

-- name: RevokeOtherSessions :exec
UPDATE sessions
SET revoked_at = now()
WHERE user_id = $1 AND id <> $2 AND revoked_at IS NULL;

-- name: RevokeAllUserSessions :exec
UPDATE sessions
SET revoked_at = now()
WHERE user_id = $1 AND revoked_at IS NULL;

-- name: DeleteExpiredSessions :exec
DELETE FROM sessions
WHERE expires_at < now() OR revoked_at IS NOT NULL;
