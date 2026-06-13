-- +goose Up
-- +goose StatementBegin
-- OAuth 2.1 Authorization Server tables — lets ChatGPT / claude.ai connect to the MCP
-- memory server via standards-based OAuth (PKCE + Dynamic Client Registration). sentinel
-- is the AS; access tokens are the same RS256 JWTs it already signs.

-- Dynamically registered clients (RFC 7591). ChatGPT/Claude self-register on first connect.
CREATE TABLE IF NOT EXISTS oauth_clients (
    client_id     TEXT        PRIMARY KEY,
    client_name   TEXT        NOT NULL DEFAULT '',
    redirect_uris TEXT[]      NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Short-lived authorization codes (single use). Only the sha256 hash is stored.
CREATE TABLE IF NOT EXISTS oauth_auth_codes (
    code_hash      TEXT        PRIMARY KEY,
    client_id      TEXT        NOT NULL,
    user_id        UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri   TEXT        NOT NULL,
    code_challenge TEXT        NOT NULL,            -- PKCE S256 challenge
    scope          TEXT        NOT NULL DEFAULT '',
    resource       TEXT        NOT NULL DEFAULT '', -- RFC 8707 resource indicator → token aud
    expires_at     TIMESTAMPTZ NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Refresh tokens so connectors stay live without re-consent. Only the hash is stored.
CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
    token_hash TEXT        PRIMARY KEY,
    client_id  TEXT        NOT NULL,
    user_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scope      TEXT        NOT NULL DEFAULT '',
    resource   TEXT        NOT NULL DEFAULT '',
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_oauth_auth_codes_expires ON oauth_auth_codes (expires_at);
CREATE INDEX IF NOT EXISTS idx_oauth_refresh_user ON oauth_refresh_tokens (user_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS oauth_refresh_tokens;
DROP TABLE IF EXISTS oauth_auth_codes;
DROP TABLE IF EXISTS oauth_clients;
-- +goose StatementEnd
