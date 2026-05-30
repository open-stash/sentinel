-- +goose Up
CREATE TABLE password_resets (
    token      TEXT        PRIMARY KEY,
    user_id    UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL DEFAULT now() + INTERVAL '1 hour',
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_password_resets_user_id ON password_resets (user_id);

-- +goose Down
DROP TABLE IF EXISTS password_resets;
