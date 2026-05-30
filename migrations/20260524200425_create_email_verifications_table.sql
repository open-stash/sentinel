-- +goose Up
CREATE TABLE email_verifications (
    token      TEXT        PRIMARY KEY,
    user_id    UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL DEFAULT now() + INTERVAL '24 hours',
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_email_verifications_user_id ON email_verifications (user_id);

-- +goose Down
DROP TABLE IF EXISTS email_verifications;
