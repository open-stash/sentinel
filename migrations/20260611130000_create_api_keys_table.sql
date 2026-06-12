-- +goose Up
-- +goose StatementBegin
-- Long-lived API keys for external MCP clients (Claude/ChatGPT/Cursor) to reach the
-- memory layer. Only the sha256 hash is stored; the plaintext `osk_…` is shown once.
CREATE TABLE IF NOT EXISTS api_keys (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT        NOT NULL DEFAULT '',
    key_hash     TEXT        NOT NULL UNIQUE,
    prefix       TEXT        NOT NULL,          -- e.g. "osk_AbCdEf" for display
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys (user_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_api_keys_user_id;
DROP TABLE IF EXISTS api_keys;
-- +goose StatementEnd
