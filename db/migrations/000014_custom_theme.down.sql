ALTER TABLE users DROP COLUMN custom_theme;
UPDATE users SET palette = 'cream' WHERE palette NOT IN ('cream','paper','sand');
ALTER TABLE users DROP CONSTRAINT users_palette_check;
ALTER TABLE users ADD CONSTRAINT users_palette_check CHECK (palette IN ('cream','paper','sand'));
