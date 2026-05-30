-- name: StoreRefreshToken :exec
INSERT INTO refresh_tokens (token, user_id, expires_at, ip_address, user_agent)
VALUES ($1, $2, $3, $4, $5);

-- name: GetRefreshToken :one
SELECT * FROM refresh_tokens
WHERE token = $1;

-- name: DeleteRefreshToken :exec
DELETE FROM refresh_tokens
WHERE token = $1;

-- name: DeleteAllRefreshTokensForUser :exec
DELETE FROM refresh_tokens
WHERE user_id = $1;

-- name: CountActiveRefreshTokensForUser :one
SELECT COUNT(*) FROM refresh_tokens
WHERE user_id = $1
  AND expires_at > now();
