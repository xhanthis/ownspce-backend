ALTER TABLE users ADD COLUMN font text NOT NULL DEFAULT 'grotesk' CHECK (font IN ('grotesk','sans','serif'));
ALTER TABLE users ADD COLUMN palette text NOT NULL DEFAULT 'cream' CHECK (palette IN ('cream','paper','sand'));
