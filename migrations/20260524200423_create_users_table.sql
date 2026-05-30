-- +goose Up
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE users (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    email             TEXT        NOT NULL UNIQUE,
    password_hash     TEXT        NOT NULL,
    role              TEXT        NOT NULL DEFAULT 'user',
    is_email_verified BOOLEAN     NOT NULL DEFAULT false,
    totp_secret       TEXT,
    totp_enabled      BOOLEAN     NOT NULL DEFAULT false,
    failed_logins     INT         NOT NULL DEFAULT 0,
    locked_until      TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_users_email ON users (email);

-- +goose Down
DROP TABLE IF EXISTS users;
