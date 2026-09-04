package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// MoneyInvite is an outstanding invitation to join a household by email.
//
// It exists alongside the encrypted product's own member flow rather than
// reusing it: that flow requires the inviter to wrap a space key for the
// invitee's devices, which presumes the invitee already has an account and a
// device key. A household inviting a parent who has never opened the app has
// neither. Accepting an invite therefore makes somebody a member but does not
// give them the space key — the ledger stays sealed until a member who already
// holds the key wraps it for their devices through MoneyKeyGaps and
// GrantSpaceKeys. An invite is permission to be handed the key, never the key.
type MoneyInvite struct {
	ID         uuid.UUID
	SpaceID    uuid.UUID
	Email      string
	Role       string
	InvitedBy  *uuid.UUID
	ExpiresAt  time.Time
	AcceptedAt *time.Time
	CreatedAt  time.Time
}

const moneyInviteColumns = `id, space_id, email, role, invited_by, expires_at, accepted_at, created_at`

func scanMoneyInvite(row pgx.Row) (*MoneyInvite, error) {
	var i MoneyInvite
	if err := row.Scan(&i.ID, &i.SpaceID, &i.Email, &i.Role, &i.InvitedBy, &i.ExpiresAt, &i.AcceptedAt, &i.CreatedAt); err != nil {
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
		if err := rows.Scan(&i.ID, &i.SpaceID, &i.Email, &i.Role, &i.InvitedBy, &i.ExpiresAt, &i.AcceptedAt, &i.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// CreateMoneyInvite records an invitation and stores only the hash of its token.
// Args: ctx, spaceID, email, role, tokenHash (32 bytes), invitedBy, expiresAt
// Returns: the invite, ErrConflict when this email already has an open invite to
// this household — re-inviting is a no-op the caller should report as success
func (s *Store) CreateMoneyInvite(ctx context.Context, spaceID uuid.UUID, email, role string, tokenHash []byte, invitedBy uuid.UUID, expiresAt time.Time) (*MoneyInvite, error) {
	i, err := scanMoneyInvite(s.pool.QueryRow(ctx, "INSERT INTO money_invites (space_id, email, role, token_hash, invited_by, expires_at) VALUES ($1, $2, $3, $4, $5, $6) RETURNING "+moneyInviteColumns, spaceID, email, role, tokenHash, invitedBy, expiresAt))
	if isUniqueViolation(err, "uq_money_invites_open") {
		return nil, ErrConflict
	}
	return i, err
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
// ErrNotFound so none of them can be told apart by probing; a caller who is
// already a member, whose existing role is kept rather than downgraded
func (s *Store) AcceptMoneyInvite(ctx context.Context, tokenHash []byte, userID uuid.UUID) (uuid.UUID, error) {
	var spaceID uuid.UUID
	err := s.tx(ctx, func(tx pgx.Tx) error {
		var inviteID uuid.UUID
		var role string
		err := tx.QueryRow(ctx, "SELECT id, space_id, role FROM money_invites WHERE token_hash = $1 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > now() FOR UPDATE", tokenHash).Scan(&inviteID, &spaceID, &role)
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
