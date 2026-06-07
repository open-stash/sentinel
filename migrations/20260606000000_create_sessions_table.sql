-- +goose Up
CREATE TABLE sessions (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash       TEXT        NOT NULL UNIQUE,   -- SHA-256 of the opaque session token
    ip_address       TEXT,
    user_agent       TEXT,
    device           TEXT,
    browser          TEXT,
    os               TEXT,
    location_city    TEXT,
    location_country TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at       TIMESTAMPTZ NOT NULL,
    revoked_at       TIMESTAMPTZ
);

CREATE INDEX idx_sessions_user_id    ON sessions (user_id);
CREATE INDEX idx_sessions_token_hash ON sessions (token_hash);

-- +goose Down
DROP TABLE IF EXISTS sessions;
