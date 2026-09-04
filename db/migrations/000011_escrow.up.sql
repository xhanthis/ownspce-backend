-- Additive only, deliberately. An earlier version of this migration renamed
-- recovery_public_key to escrow_public_key, which took the deployed API down the
-- moment it was applied: the running code still selected the old name. A
-- migration has to be safe to apply BEFORE the code that needs it ships, so the
-- column keeps its historical name and only the new secret is added beside it.
ALTER TABLE users ADD COLUMN IF NOT EXISTS escrow_private_key bytea;
