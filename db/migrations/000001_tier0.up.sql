CREATE EXTENSION IF NOT EXISTS citext;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE users (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), email citext NOT NULL UNIQUE, google_sub text UNIQUE, apple_sub text UNIQUE, name text NOT NULL DEFAULT '', username citext UNIQUE CHECK (username ~ '^[a-z0-9_]{3,30}$'), avatar_url text, plan text NOT NULL DEFAULT 'free' CHECK (plan IN ('free','pro','team')), recovery_public_key bytea CHECK (recovery_public_key IS NULL OR octet_length(recovery_public_key) = 32), streak_count int NOT NULL DEFAULT 0 CHECK (streak_count >= 0), streak_updated_on date, theme text NOT NULL DEFAULT 'system' CHECK (theme IN ('system','light','dark')), language text NOT NULL DEFAULT 'en', notify_email boolean NOT NULL DEFAULT true, notify_push boolean NOT NULL DEFAULT true, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());

CREATE TABLE devices (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, label text NOT NULL DEFAULT '', platform text NOT NULL DEFAULT '' CHECK (platform IN ('','ios','macos','android','windows','linux','web')), public_key bytea NOT NULL CHECK (octet_length(public_key) = 32), status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','active','revoked')), approved_by_device uuid REFERENCES devices(id) ON DELETE SET NULL, created_at timestamptz NOT NULL DEFAULT now(), last_seen_at timestamptz, revoked_at timestamptz);
CREATE INDEX idx_devices_user_live ON devices (user_id) WHERE status <> 'revoked';
CREATE UNIQUE INDEX uq_devices_user_key ON devices (user_id, public_key) WHERE status <> 'revoked';

CREATE TABLE refresh_tokens (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE, token_hash bytea NOT NULL UNIQUE, family_id uuid NOT NULL, expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), used_at timestamptz, revoked_at timestamptz);
CREATE INDEX idx_refresh_family ON refresh_tokens (family_id);
CREATE INDEX idx_refresh_device ON refresh_tokens (device_id);

CREATE TABLE rate_limits (bucket_key text NOT NULL, window_start timestamptz NOT NULL, count int NOT NULL DEFAULT 1, PRIMARY KEY (bucket_key, window_start));
CREATE INDEX idx_rate_limits_window ON rate_limits (window_start);
