ALTER TABLE users DROP CONSTRAINT users_palette_check;
ALTER TABLE users ADD CONSTRAINT users_palette_check CHECK (palette IN ('cream','paper','sand','graphite','midnight','indigo','evergreen'));
ALTER TABLE users ADD COLUMN custom_theme jsonb;
