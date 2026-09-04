ALTER TABLE users RENAME COLUMN recovery_public_key TO escrow_public_key;
ALTER TABLE users ADD COLUMN escrow_private_key bytea;
