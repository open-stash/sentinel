-- name: CreateEmailVerification :exec
INSERT INTO email_verifications (token, user_id, expires_at)
VALUES ($1, $2, $3);

-- name: GetEmailVerification :one
SELECT * FROM email_verifications
WHERE token = $1;

-- name: MarkEmailVerificationUsed :exec
UPDATE email_verifications
SET used_at = now()
WHERE token = $1;

-- name: DeleteExpiredEmailVerifications :exec
DELETE FROM email_verifications
WHERE expires_at < now();
