package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// MoneyInvite is an invitation to join a household by email.
//
// An invite used to be permission to be handed the key and never the key
// itself: the invitee accepted, became a member, and then waited for somebody
// who already held the household key to wrap it for their devices. That wait
// was the product's worst screen. Somebody invited to a family ledger opened it
// and found nothing, with no action available to them and no idea who they were
// waiting on.
//
// So the key travels with the invite now. Creating one provisions the invited
// address an account escrow identity, the owner wraps the household key to it
// while they still hold the plaintext, and FileMoneyInviteKey lands the
// membership and that wrap together. The invitee signs in and the ledger opens
// — no second step, and nobody to wait for.
//
// InviteeUserID is that provisioned account. KeyFiledAt is the moment the wrap
// landed; until then the invite is real but the ledger behind it is not yet
// readable, which is a state the owner is shown rather than one the invitee
// discovers.
type MoneyInvite struct {
	ID            uuid.UUID
	SpaceID       uuid.UUID
	Email         string
	Role          string
	InvitedBy     *uuid.UUID
	InviteeUserID *uuid.UUID
	ExpiresAt     time.Time
	AcceptedAt    *time.Time
	KeyFiledAt    *time.Time
	CreatedAt     time.Time
}

const moneyInviteColumns = `id, space_id, email, role, invited_by, invitee_user_id, expires_at, accepted_at, key_filed_at, created_at`

func scanMoneyInvite(row pgx.Row) (*MoneyInvite, error) {
	var i MoneyInvite
	if err := row.Scan(&i.ID, &i.SpaceID, &i.Email, &i.Role, &i.InvitedBy, &i.InviteeUserID, &i.ExpiresAt, &i.AcceptedAt, &i.KeyFiledAt, &i.CreatedAt); err != nil {
		if noRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &i, nil
}

// ListMoneyInvites returns the household's outstanding invitations.
// Args: ctx, spaceID
// Returns: open, unexpired invites, error
func (s *Store) ListMoneyInvites(ctx context.Context, spaceID uuid.UUID) ([]MoneyInvite, error) {
	rows, err := s.pool.Query(ctx, "SELECT "+moneyInviteColumns+" FROM money_invites WHERE space_id = $1 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > now() ORDER BY created_at DESC", spaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []MoneyInvite
	for rows.Next() {
		var i MoneyInvite
		if err := rows.Scan(&i.ID, &i.SpaceID, &i.Email, &i.Role, &i.InvitedBy, &i.InviteeUserID, &i.ExpiresAt, &i.AcceptedAt, &i.KeyFiledAt, &i.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// CreateMoneyInvite records an invitation and stores only the hash of its token.
// Args: ctx, spaceID, email, role, tokenHash (32 bytes), invitedBy, inviteeUserID
// (the account provisioned for the address, nil when escrow is unavailable and
// the household key cannot travel with the invite), expiresAt
// Returns: the invite, ErrConflict when this email already has an open invite to
// this household — re-inviting is a no-op the caller should report as success
func (s *Store) CreateMoneyInvite(ctx context.Context, spaceID uuid.UUID, email, role string, tokenHash []byte, invitedBy uuid.UUID, inviteeUserID *uuid.UUID, expiresAt time.Time) (*MoneyInvite, error) {
	i, err := scanMoneyInvite(s.pool.QueryRow(ctx, "INSERT INTO money_invites (space_id, email, role, token_hash, invited_by, invitee_user_id, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING "+moneyInviteColumns, spaceID, email, role, tokenHash, invitedBy, inviteeUserID, expiresAt))
	if isUniqueViolation(err, "uq_money_invites_open") {
		return nil, ErrConflict
	}
	return i, err
}

// FileMoneyInviteKey lands the household key on an invitation, which is what
// makes the invitee a member who can actually read the ledger.
//
// One transaction does all three things, because any two of them without the
// third is a state somebody has to be told about: the membership, the household
// key sealed to the invitee's account escrow identity, and the stamp that
// closes the invite. A member with no key is the screen this whole change
// exists to delete; a key with no membership is unreadable anyway, since every
// read goes through space_members first.
//
// The invite is marked accepted here rather than when somebody clicks the link.
// The link is now navigation, not permission — the person is already in by the
// time they follow it.
// Args: ctx, spaceID, inviteID, actorID (the owner wrapping the key), epoch (the
// household's current key epoch as the owner saw it), wrappedKey (the household
// key sealed to the invitee's escrow public key)
// Returns: the invitee's user id, error
// Handles: an invite that is unknown, revoked, expired or already filed
// (ErrNotFound, so a replayed call cannot re-add somebody an owner has since
// removed); an invite created before an escrow identity could be provisioned
// (ErrForbidden — there is nobody to seal to); a rotation that raced the wrap
// (ErrConflict, so the owner refetches and retries rather than filing a key
// nobody can open); and an invitee who is somehow already a member, whose
// existing role is left alone
func (s *Store) FileMoneyInviteKey(ctx context.Context, spaceID, inviteID, actorID uuid.UUID, epoch int, wrappedKey []byte) (uuid.UUID, error) {
	var inviteeID uuid.UUID
	err := s.tx(ctx, func(tx pgx.Tx) error {
		var role string
		var invitee *uuid.UUID
		err := tx.QueryRow(ctx, "SELECT role, invitee_user_id FROM money_invites WHERE id = $1 AND space_id = $2 AND accepted_at IS NULL AND key_filed_at IS NULL AND revoked_at IS NULL AND expires_at > now() FOR UPDATE", inviteID, spaceID).Scan(&role, &invitee)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if invitee == nil {
			return ErrForbidden
		}
		inviteeID = *invitee

		var current int
		if err := tx.QueryRow(ctx, "SELECT key_epoch FROM spaces WHERE id = $1 AND deleted_at IS NULL FOR UPDATE", spaceID).Scan(&current); err != nil {
			if noRows(err) {
				return ErrNotFound
			}
			return err
		}
		if current != epoch {
			return ErrConflict
		}

		if _, err := tx.Exec(ctx, "INSERT INTO space_members (space_id, user_id, role, invited_by) VALUES ($1, $2, $3, $4) ON CONFLICT (space_id, user_id) DO NOTHING", spaceID, inviteeID, role, actorID); err != nil {
			return err
		}

		inserted, err := insertWrappedKeys(ctx, tx, spaceID, epoch, inviteeID, actorID, []DeviceWrappedKey{{WrappedKey: wrappedKey}})
		if err != nil {
			return err
		}
		if inserted == 0 {
			// insertWrappedKeys files an escrow wrap only for an account that
			// has an escrow public key to seal to. Nothing landed, so the
			// invitee would join to a ledger they cannot read — refuse the whole
			// transaction rather than create that member.
			return ErrForbidden
		}

		_, err = tx.Exec(ctx, "UPDATE money_invites SET key_filed_at = now(), accepted_at = now(), accepted_by = $2 WHERE id = $1", inviteID, inviteeID)
		return err
	})
	if err != nil {
		return uuid.Nil, err
	}
	return inviteeID, nil
}

// RevokeMoneyInvite withdraws an outstanding invitation.
// Args: ctx, spaceID, inviteID
// Returns: error, ErrNotFound when nothing open matched
func (s *Store) RevokeMoneyInvite(ctx context.Context, spaceID, inviteID uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, "UPDATE money_invites SET revoked_at = now() WHERE space_id = $1 AND id = $2 AND accepted_at IS NULL AND revoked_at IS NULL", spaceID, inviteID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// AcceptMoneyInvite redeems an invitation token and adds the caller to the
// household, in one transaction so a redeemed token can never be spent twice.
//
// The invite's email is not checked against the caller's: the token is the
// capability, and requiring both would lock out anyone whose Google address
// differs from the one a family member typed. Expiry and single use are what
// bound it.
// Args: ctx, tokenHash (32 bytes), userID
// Returns: the space joined, error
// Handles: an unknown, expired, revoked or already-redeemed token, all
// ErrNotFound so none of them can be told apart by probing — except a token the
// caller themselves already redeemed, which resolves to the same household
// again, because somebody re-opening the link they were sent should land on the
// ledger rather than on "no longer valid"; and a caller who is already a member,
// whose existing role is kept rather than downgraded
func (s *Store) AcceptMoneyInvite(ctx context.Context, tokenHash []byte, userID uuid.UUID) (uuid.UUID, error) {
	var spaceID uuid.UUID
	err := s.tx(ctx, func(tx pgx.Tx) error {
		var inviteID uuid.UUID
		var role string
		err := tx.QueryRow(ctx, "SELECT id, space_id, role FROM money_invites WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now() AND (accepted_at IS NULL OR accepted_by = $2) FOR UPDATE", tokenHash, userID).Scan(&inviteID, &spaceID, &role)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if _, err := tx.Exec(ctx, "INSERT INTO space_members (space_id, user_id, role) VALUES ($1, $2, $3) ON CONFLICT (space_id, user_id) DO NOTHING", spaceID, userID, role); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, "UPDATE money_invites SET accepted_at = now(), accepted_by = $2 WHERE id = $1", inviteID, userID)
		return err
	})
	if err != nil {
		return uuid.Nil, err
	}
	return spaceID, nil
}
