CREATE TABLE IF NOT EXISTS home_users (id uuid PRIMARY KEY, username text NOT NULL UNIQUE, name text NOT NULL, password_hash text NOT NULL, theme text NOT NULL DEFAULT 'system', palette text NOT NULL DEFAULT 'cream', font text NOT NULL DEFAULT 'grotesk', created_at timestamptz NOT NULL DEFAULT now());

CREATE TABLE IF NOT EXISTS home_sessions (token_hash text PRIMARY KEY, user_id uuid NOT NULL REFERENCES home_users(id) ON DELETE CASCADE, created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL);
CREATE INDEX IF NOT EXISTS home_sessions_user_idx ON home_sessions (user_id);

CREATE TABLE IF NOT EXISTS home_settings (id smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1), name text NOT NULL DEFAULT 'Home', currency text NOT NULL DEFAULT 'INR', shared_by_default boolean NOT NULL DEFAULT true, income_tracking boolean NOT NULL DEFAULT true, overall_budget_minor bigint CHECK (overall_budget_minor > 0), updated_at timestamptz NOT NULL DEFAULT now());
INSERT INTO home_settings (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS home_categories (id uuid PRIMARY KEY, name text NOT NULL, emoji text NOT NULL, color text NOT NULL, kind text NOT NULL CHECK (kind IN ('expense', 'income')), sort_order integer NOT NULL, archived boolean NOT NULL DEFAULT false);

CREATE TABLE IF NOT EXISTS home_entries (id uuid PRIMARY KEY, occurred_on date NOT NULL, type text NOT NULL CHECK (type IN ('expense', 'income')), amount_minor bigint NOT NULL CHECK (amount_minor > 0), category_id uuid NOT NULL REFERENCES home_categories(id), note text NOT NULL DEFAULT '', is_shared boolean NOT NULL, paid_by uuid REFERENCES home_users(id) ON DELETE SET NULL, created_by uuid REFERENCES home_users(id) ON DELETE SET NULL, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS home_entries_occurred_idx ON home_entries (occurred_on DESC, id DESC);

CREATE TABLE IF NOT EXISTS home_budgets (category_id uuid PRIMARY KEY REFERENCES home_categories(id) ON DELETE CASCADE, limit_minor bigint NOT NULL CHECK (limit_minor > 0), updated_at timestamptz NOT NULL DEFAULT now());

CREATE TABLE IF NOT EXISTS home_holdings (id uuid PRIMARY KEY, owner_id uuid REFERENCES home_users(id) ON DELETE SET NULL, name text NOT NULL, badge text NOT NULL, asset_type text NOT NULL, units numeric(24, 6) NOT NULL CHECK (units >= 0), avg_cost_minor bigint NOT NULL CHECK (avg_cost_minor >= 0), last_price_minor bigint NOT NULL CHECK (last_price_minor >= 0), sip_minor bigint NOT NULL DEFAULT 0 CHECK (sip_minor >= 0), color text NOT NULL, note text NOT NULL DEFAULT '', priced_at timestamptz NOT NULL DEFAULT now(), created_at timestamptz NOT NULL DEFAULT now());

CREATE TABLE IF NOT EXISTS home_login_failures (username text NOT NULL, window_start timestamptz NOT NULL, failures integer NOT NULL DEFAULT 1, PRIMARY KEY (username, window_start));
CREATE INDEX IF NOT EXISTS home_login_failures_window_idx ON home_login_failures (window_start);
