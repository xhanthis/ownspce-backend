-- The household approver is gone: an invite now carries the household key,
-- wrapped to an escrow identity the server provisions for the invited address.
-- Two columns record who that identity is and whether the wrap has landed.
--
-- Additive only, and deliberately so — 000011's note explains why. Nothing here
-- changes devices.status or space_keys, so the previous binary still starts if
-- this is rolled back: it reads neither column, and the escrow rows written in
-- the meantime are exactly what its own restoreFromEscrow already spent.
ALTER TABLE money_invites ADD COLUMN IF NOT EXISTS invitee_user_id uuid REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE money_invites ADD COLUMN IF NOT EXISTS key_filed_at timestamptz;
