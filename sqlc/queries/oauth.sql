-- name: CreateOAuthClient :one
INSERT INTO oauth_clients (client_id, client_name, redirect_uris)
VALUES ($1, $2, $3)
RETURNING *;

-- name: GetOAuthClient :one
SELECT * FROM oauth_clients
WHERE client_id = $1;

-- name: CreateAuthCode :exec
INSERT INTO oauth_auth_codes (
    code_hash, client_id, user_id, redirect_uri, code_challenge, scope, resource, expires_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: GetAuthCode :one
SELECT * FROM oauth_auth_codes
WHERE code_hash = $1;

-- name: DeleteAuthCode :exec
DELETE FROM oauth_auth_codes
WHERE code_hash = $1;

-- name: CreateOAuthRefreshToken :exec
INSERT INTO oauth_refresh_tokens (token_hash, client_id, user_id, scope, resource, expires_at)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: GetOAuthRefreshToken :one
SELECT * FROM oauth_refresh_tokens
WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now();

-- name: RevokeOAuthRefreshToken :exec
UPDATE oauth_refresh_tokens
SET revoked_at = now()
WHERE token_hash = $1;
