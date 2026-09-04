CREATE TABLE email_codes (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), email citext NOT NULL, purpose text NOT NULL CHECK (purpose IN ('signin','device')), user_id uuid REFERENCES users(id) ON DELETE CASCADE, device_id uuid REFERENCES devices(id) ON DELETE CASCADE, code_hash bytea NOT NULL CHECK (octet_length(code_hash) = 32), attempts int NOT NULL DEFAULT 0 CHECK (attempts >= 0), expires_at timestamptz NOT NULL, consumed_at timestamptz, created_at timestamptz NOT NULL DEFAULT now(), CHECK (purpose <> 'device' OR device_id IS NOT NULL));
CREATE INDEX idx_email_codes_live ON email_codes (email, purpose, created_at DESC) WHERE consumed_at IS NULL;
CREATE INDEX idx_email_codes_expiry ON email_codes (expires_at);

ALTER TABLE devices ADD COLUMN approved_via text CHECK (approved_via IS NULL OR approved_via IN ('first','device','recovery','email'));
UPDATE devices SET approved_via = CASE WHEN approved_by_device IS NOT NULL THEN 'device' WHEN status = 'active' THEN 'first' END;
