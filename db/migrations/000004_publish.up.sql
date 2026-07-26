CREATE TABLE publishes (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, slug citext NOT NULL CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,63}$'), html_blob_url text NOT NULL, blocks_blob_url text NOT NULL, asset_blob_urls jsonb NOT NULL DEFAULT '[]', og_title text NOT NULL DEFAULT '', og_description text NOT NULL DEFAULT '', size_bytes bigint NOT NULL CHECK (size_bytes >= 0), status text NOT NULL DEFAULT 'live' CHECK (status IN ('live','taken_down')), published_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(), UNIQUE (user_id, slug));
CREATE INDEX idx_publishes_user ON publishes (user_id);

CREATE TABLE reserved_names (name citext PRIMARY KEY);
INSERT INTO reserved_names (name) VALUES ('api'),('www'),('app'),('admin'),('root'),('support'),('help'),('blog'),('docs'),('about'),('ownspce'),('static'),('cdn'),('mail'),('status'),('terms'),('privacy'),('settings'),('login'),('signup'),('me'),('public'),('assets'),('billing'),('security');

CREATE TABLE abuse_reports (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), publish_id uuid REFERENCES publishes(id) ON DELETE CASCADE, reporter_ip_hash bytea, reason text NOT NULL DEFAULT '', details text NOT NULL DEFAULT '', created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX idx_abuse_publish ON abuse_reports (publish_id);
