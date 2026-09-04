-- Intentionally a no-op. Rolling back must not take escrow_private_key away:
-- it is the only copy of every account's escrow key, and destroying it would
-- make every household created since this shipped permanently unrecoverable.
-- Removing the column is a deliberate, separate act, not a rollback.
SELECT 1;
