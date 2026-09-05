CREATE TABLE shares (id uuid PRIMARY KEY, space_id uuid NOT NULL REFERENCES spaces(id) ON DELETE CASCADE, ciphertext bytea NOT NULL, size_bytes bigint NOT NULL CHECK (size_bytes > 0), created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX idx_shares_space ON shares (space_id);

CREATE TABLE attachments (id uuid PRIMARY KEY, space_id uuid NOT NULL REFERENCES spaces(id) ON DELETE CASCADE, blob_url text NOT NULL, size_bytes bigint NOT NULL CHECK (size_bytes >= 0), created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX idx_attachments_space ON attachments (space_id);
