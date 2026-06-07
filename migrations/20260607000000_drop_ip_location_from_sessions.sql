-- +goose Up
-- IP (always loopback/proxy noise locally) and location (never resolved — no geo
-- provider) carried no real value, so they were dropped from session metadata.
ALTER TABLE sessions DROP COLUMN IF EXISTS ip_address;
ALTER TABLE sessions DROP COLUMN IF EXISTS location_city;
ALTER TABLE sessions DROP COLUMN IF EXISTS location_country;

-- +goose Down
ALTER TABLE sessions ADD COLUMN ip_address TEXT;
ALTER TABLE sessions ADD COLUMN location_city TEXT;
ALTER TABLE sessions ADD COLUMN location_country TEXT;
