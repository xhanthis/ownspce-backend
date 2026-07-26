CREATE TABLE spaces (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), owner_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, key_epoch int NOT NULL DEFAULT 1 CHECK (key_epoch > 0), head_seq bigint NOT NULL DEFAULT 0, oldest_seq bigint NOT NULL DEFAULT 1, created_at timestamptz NOT NULL DEFAULT now(), deleted_at timestamptz);
CREATE INDEX idx_spaces_owner ON spaces (owner_id) WHERE deleted_at IS NULL;

CREATE TABLE space_members (space_id uuid NOT NULL REFERENCES spaces(id) ON DELETE CASCADE, user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, role text NOT NULL CHECK (role IN ('owner','editor','viewer')), invited_by uuid REFERENCES users(id) ON DELETE SET NULL, created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (space_id, user_id));
CREATE INDEX idx_members_user ON space_members (user_id);

CREATE TABLE space_keys (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), space_id uuid NOT NULL REFERENCES spaces(id) ON DELETE CASCADE, user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, device_id uuid REFERENCES devices(id) ON DELETE CASCADE, key_epoch int NOT NULL CHECK (key_epoch > 0), wrapped_key bytea NOT NULL CHECK (octet_length(wrapped_key) BETWEEN 48 AND 256), created_by uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, created_at timestamptz NOT NULL DEFAULT now());
CREATE UNIQUE INDEX uq_space_keys ON space_keys (space_id, key_epoch, user_id, COALESCE(device_id, '00000000-0000-0000-0000-000000000000'::uuid));
CREATE INDEX idx_space_keys_device ON space_keys (device_id);
CREATE INDEX idx_space_keys_user ON space_keys (user_id, space_id);

CREATE TABLE space_changes (space_id uuid NOT NULL REFERENCES spaces(id) ON DELETE CASCADE, seq bigint NOT NULL, cid uuid NOT NULL, key_epoch int NOT NULL, author_device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE, ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) <= 262184), created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (space_id, seq));
CREATE UNIQUE INDEX uq_changes_cid ON space_changes (space_id, cid);

CREATE TABLE space_snapshots (space_id uuid PRIMARY KEY REFERENCES spaces(id) ON DELETE CASCADE, upto_seq bigint NOT NULL, key_epoch int NOT NULL, storage text NOT NULL CHECK (storage IN ('inline','blob')), ciphertext bytea, blob_url text, size_bucket int NOT NULL, created_by_device uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE, created_at timestamptz NOT NULL DEFAULT now(), CHECK ((storage = 'inline' AND ciphertext IS NOT NULL AND blob_url IS NULL) OR (storage = 'blob' AND blob_url IS NOT NULL AND ciphertext IS NULL)));
