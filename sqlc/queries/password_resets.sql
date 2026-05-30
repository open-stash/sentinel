-- name: CreatePasswordReset :exec
INSERT INTO password_resets (token, user_id, expires_at)
VALUES ($1, $2, $3);

-- name: GetPasswordReset :one
SELECT * FROM password_resets
WHERE token = $1;

-- name: MarkPasswordResetUsed :exec
UPDATE password_resets
SET used_at = now()
WHERE token = $1;

-- name: DeleteExpiredPasswordResets :exec
DELETE FROM password_resets
WHERE expires_at < now();
