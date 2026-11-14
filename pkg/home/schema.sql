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

CREATE TABLE IF NOT EXISTS home_meals (id uuid PRIMARY KEY, day date NOT NULL, slot text NOT NULL CHECK (slot IN ('breakfast', 'lunch', 'snack', 'dinner', 'late')), name text NOT NULL, kcal integer NOT NULL CHECK (kcal >= 0), protein_g integer NOT NULL DEFAULT 0 CHECK (protein_g >= 0), carbs_g integer NOT NULL DEFAULT 0 CHECK (carbs_g >= 0), fat_g integer NOT NULL DEFAULT 0 CHECK (fat_g >= 0), serves integer NOT NULL DEFAULT 2 CHECK (serves > 0), ingredients jsonb NOT NULL DEFAULT '[]'::jsonb, sort_order integer NOT NULL DEFAULT 0, created_by uuid REFERENCES home_users(id) ON DELETE SET NULL, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS home_meals_day_idx ON home_meals (day DESC, sort_order, id);
ALTER TABLE home_meals DROP CONSTRAINT IF EXISTS home_meals_slot_check, ADD CONSTRAINT home_meals_slot_check CHECK (slot IN ('breakfast', 'lunch', 'snack', 'dinner', 'late'));

CREATE TABLE IF NOT EXISTS home_meal_ticks (meal_id uuid NOT NULL REFERENCES home_meals(id) ON DELETE CASCADE, user_id uuid NOT NULL REFERENCES home_users(id) ON DELETE CASCADE, ticked_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (meal_id, user_id));
ALTER TABLE home_meal_ticks ADD COLUMN IF NOT EXISTS portion numeric(4,2) NOT NULL DEFAULT 1 CHECK (portion > 0 AND portion <= 5);

CREATE TABLE IF NOT EXISTS home_dishes (id uuid PRIMARY KEY, name text NOT NULL, name_key text NOT NULL UNIQUE, kcal integer NOT NULL CHECK (kcal >= 0), protein_g integer NOT NULL DEFAULT 0 CHECK (protein_g >= 0), carbs_g integer NOT NULL DEFAULT 0 CHECK (carbs_g >= 0), fat_g integer NOT NULL DEFAULT 0 CHECK (fat_g >= 0), serves integer NOT NULL DEFAULT 2 CHECK (serves > 0), ingredients jsonb NOT NULL DEFAULT '[]'::jsonb, times_used integer NOT NULL DEFAULT 0, last_used_at timestamptz NOT NULL DEFAULT now(), created_by uuid REFERENCES home_users(id) ON DELETE SET NULL, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS home_dishes_recent_idx ON home_dishes (last_used_at DESC, times_used DESC);
ALTER TABLE home_meals ADD COLUMN IF NOT EXISTS dish_id uuid REFERENCES home_dishes(id) ON DELETE SET NULL;

CREATE TABLE IF NOT EXISTS home_body_profiles (user_id uuid PRIMARY KEY REFERENCES home_users(id) ON DELETE CASCADE, height_cm integer CHECK (height_cm BETWEEN 100 AND 250), birth_year integer CHECK (birth_year BETWEEN 1900 AND 2100), sex text CHECK (sex IN ('male', 'female')), goal_weight_g integer CHECK (goal_weight_g BETWEEN 20000 AND 400000), goal_fat_x10 integer CHECK (goal_fat_x10 BETWEEN 10 AND 700), weekly_g integer NOT NULL DEFAULT 500 CHECK (weekly_g BETWEEN 100 AND 1000), health_sync boolean NOT NULL DEFAULT false, updated_at timestamptz NOT NULL DEFAULT now());

CREATE TABLE IF NOT EXISTS home_body_days (user_id uuid NOT NULL REFERENCES home_users(id) ON DELETE CASCADE, day date NOT NULL, weight_g integer CHECK (weight_g BETWEEN 20000 AND 400000), fat_x10 integer CHECK (fat_x10 BETWEEN 10 AND 700), weight_source text CHECK (weight_source IN ('health', 'manual')), active_kcal integer NOT NULL DEFAULT 0 CHECK (active_kcal >= 0), basal_kcal integer CHECK (basal_kcal >= 0), exercise_min integer NOT NULL DEFAULT 0 CHECK (exercise_min >= 0), steps integer NOT NULL DEFAULT 0 CHECK (steps >= 0), workouts jsonb NOT NULL DEFAULT '[]'::jsonb, updated_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (user_id, day));

-- Insights: a night's sleep beside the day's steps, a protein target on the profile, and whether a meal was ordered in.
ALTER TABLE home_body_days ADD COLUMN IF NOT EXISTS sleep_min integer CHECK (sleep_min BETWEEN 0 AND 1440), ADD COLUMN IF NOT EXISTS sleep_source text CHECK (sleep_source IN ('health', 'manual'));
ALTER TABLE home_body_profiles ADD COLUMN IF NOT EXISTS protein_g integer CHECK (protein_g BETWEEN 20 AND 400);
ALTER TABLE home_body_profiles ADD COLUMN IF NOT EXISTS goal_by date;
ALTER TABLE home_meals ADD COLUMN IF NOT EXISTS ordered_in boolean NOT NULL DEFAULT false;
CREATE TABLE IF NOT EXISTS home_insight_notes (user_id uuid NOT NULL REFERENCES home_users(id) ON DELETE CASCADE, figures_hash text NOT NULL, note text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (user_id, figures_hash));
CREATE INDEX IF NOT EXISTS home_insight_notes_user_created_idx ON home_insight_notes (user_id, created_at DESC);

-- AI meal ideas for a day: dishes for empty slots and better options for planned ones, kept per exact input so the same day is never asked twice.
CREATE TABLE IF NOT EXISTS home_meal_ideas (user_id uuid NOT NULL REFERENCES home_users(id) ON DELETE CASCADE, input_hash text NOT NULL, day date NOT NULL, ideas jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (user_id, input_hash));
CREATE INDEX IF NOT EXISTS home_meal_ideas_user_created_idx ON home_meal_ideas (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS home_meal_ideas_user_day_idx ON home_meal_ideas (user_id, day, created_at DESC);

-- Model calls a member asked for, so a daily cap holds: Vit messages and new meal ideas. A reservation not marked done stops counting after a minute.
CREATE TABLE IF NOT EXISTS home_ai_uses (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL REFERENCES home_users(id) ON DELETE CASCADE, kind text NOT NULL CHECK (kind IN ('vit', 'idea_again')), done boolean NOT NULL DEFAULT false, created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS home_ai_uses_user_kind_created_idx ON home_ai_uses (user_id, kind, created_at DESC);
