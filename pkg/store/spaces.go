package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	RoleOwner  = "owner"
	RoleEditor = "editor"
	RoleViewer = "viewer"
)

// roleRank orders roles so middleware can express "editor or better".
var roleRank = map[string]int{RoleViewer: 1, RoleEditor: 2, RoleOwner: 3}

// RoleAtLeast reports whether have satisfies the want threshold.
func RoleAtLeast(have, want string) bool { return roleRank[have] >= roleRank[want] }

// SpaceSummary is everything a client needs to start syncing a space. The space
// NAME is absent by design — it lives encrypted inside the workspace document.
type SpaceSummary struct {
	ID               uuid.UUID
	Role             string
	KeyEpoch         int
	HeadSeq          int64
	OldestSeq        int64
	WorkspaceVersion int64
	MemberCount      int
	WrappedKey       []byte
}

// SpaceMeta is the hot-path sync state of a space.
type SpaceMeta struct {
	ID        uuid.UUID
	KeyEpoch  int
	HeadSeq   int64
	OldestSeq int64
}

// DeviceWrappedKey is a space key sealed to one of the caller's own devices, or
// to the account recovery key when DeviceID is nil.
type DeviceWrappedKey struct {
	DeviceID   *uuid.UUID
	WrappedKey []byte
}

// CreateSpace creates a space owned by userID and stores the space key wrapped
// for the owner's devices and recovery key.
// Args: ctx, ownerID, keys (wrapped space keys; DeviceID nil means recovery wrap)
// Returns: space id, error
// Handles: keys naming devices that are not the owner's active devices (skipped),
// zero usable keys (ErrForbidden — a space nobody can decrypt is never created)
func (s *Store) CreateSpace(ctx context.Context, ownerID uuid.UUID, keys []DeviceWrappedKey) (uuid.UUID, error) {
	var spaceID uuid.UUID
	err := s.tx(ctx, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, "INSERT INTO spaces (owner_id) VALUES ($1) RETURNING id", ownerID).Scan(&spaceID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "INSERT INTO space_members (space_id, user_id, role, invited_by) VALUES ($1, $2, 'owner', $2)", spaceID, ownerID); err != nil {
			return err
		}
		inserted, err := insertWrappedKeys(ctx, tx, spaceID, 1, ownerID, ownerID, keys)
		if err != nil {
			return err
		}
		if inserted == 0 {
			return ErrForbidden
		}
		return nil
	})
	return spaceID, err
}

// insertWrappedKeys stores wrapped space keys for one member, letting Postgres
// enforce that each named device really is an active device of that member. The
// rows go out in one pgx batch: a single round trip, and no array parameters,
// which the PgBouncer-safe exec query mode cannot encode.
func insertWrappedKeys(ctx context.Context, tx pgx.Tx, spaceID uuid.UUID, epoch int, memberID, actorID uuid.UUID, keys []DeviceWrappedKey) (int64, error) {
	if len(keys) == 0 {
		return 0, nil
	}

	batch := &pgx.Batch{}
	for _, k := range keys {
		if k.DeviceID == nil {
			batch.Queue("INSERT INTO space_keys (space_id, user_id, device_id, key_epoch, wrapped_key, created_by) SELECT $1, $2, NULL, $3, $4, $5 WHERE EXISTS (SELECT 1 FROM users u WHERE u.id = $2 AND u.recovery_public_key IS NOT NULL) ON CONFLICT DO NOTHING", spaceID, memberID, epoch, k.WrappedKey, actorID)
			continue
		}
		batch.Queue("INSERT INTO space_keys (space_id, user_id, device_id, key_epoch, wrapped_key, created_by) SELECT $1, $2, d.id, $3, $4, $5 FROM devices d WHERE d.id = $6 AND d.user_id = $2 AND d.status = 'active' ON CONFLICT DO NOTHING", spaceID, memberID, epoch, k.WrappedKey, actorID, *k.DeviceID)
	}

	results := tx.SendBatch(ctx, batch)
	var count int64
	for range keys {
		tag, err := results.Exec()
		if err != nil {
			results.Close()
			return 0, err
		}
		count += tag.RowsAffected()
	}
	if err := results.Close(); err != nil {
		return 0, err
	}
	return count, nil
}

// ListSpaces returns every space the user belongs to, each carrying the space key
// wrapped for the calling device so that device can begin decrypting immediately.
//
// The account's escrow copy of the key is deliberately not selected. It is
// sealed to a key only the server can open, so no caller could use it, and
// handing out ciphertext nobody can read is surface without a purpose.
// Args: ctx, userID, deviceID (calling device)
// Returns: summaries ordered by creation, error
// Handles: spaces whose key is not yet wrapped for this device (WrappedKey nil —
// the device has not been let in)
func (s *Store) ListSpaces(ctx context.Context, userID, deviceID uuid.UUID) ([]SpaceSummary, error) {
	rows, err := s.pool.Query(ctx, "SELECT s.id, m.role, s.key_epoch, s.head_seq, s.oldest_seq, COALESCE(w.version, 0), (SELECT count(*) FROM space_members mm WHERE mm.space_id = s.id), dk.wrapped_key FROM space_members m JOIN spaces s ON s.id = m.space_id AND s.deleted_at IS NULL LEFT JOIN workspace_docs w ON w.space_id = s.id LEFT JOIN space_keys dk ON dk.space_id = s.id AND dk.key_epoch = s.key_epoch AND dk.user_id = m.user_id AND dk.device_id = $2 WHERE m.user_id = $1 ORDER BY s.created_at ASC", userID, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []SpaceSummary
	for rows.Next() {
		var sp SpaceSummary
		if err := rows.Scan(&sp.ID, &sp.Role, &sp.KeyEpoch, &sp.HeadSeq, &sp.OldestSeq, &sp.WorkspaceVersion, &sp.MemberCount, &sp.WrappedKey); err != nil {
			return nil, err
		}
		out = append(out, sp)
	}
	return out, rows.Err()
}

// SpaceRole returns the caller's role in a space, or ErrNotFound when they are not
// a member — the single authorization gate for every space-scoped route.
func (s *Store) SpaceRole(ctx context.Context, spaceID, userID uuid.UUID) (string, error) {
	var role string
	err := s.pool.QueryRow(ctx, "SELECT m.role FROM space_members m JOIN spaces s ON s.id = m.space_id AND s.deleted_at IS NULL WHERE m.space_id = $1 AND m.user_id = $2", spaceID, userID).Scan(&role)
	if err != nil {
		if noRows(err) {
			return "", ErrNotFound
		}
		return "", err
	}
	return role, nil
}

func (s *Store) SpaceMeta(ctx context.Context, spaceID uuid.UUID) (*SpaceMeta, error) {
	var m SpaceMeta
	err := s.pool.QueryRow(ctx, "SELECT id, key_epoch, head_seq, oldest_seq FROM spaces WHERE id = $1 AND deleted_at IS NULL", spaceID).Scan(&m.ID, &m.KeyEpoch, &m.HeadSeq, &m.OldestSeq)
	if err != nil {
		if noRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &m, nil
}

// Member is a space participant, described only with Tier 0 identity fields.
type Member struct {
	UserID    uuid.UUID
	Username  *string
	Name      string
	AvatarURL *string
	Role      string
	JoinedAt  time.Time
}

func (s *Store) ListMembers(ctx context.Context, spaceID uuid.UUID) ([]Member, error) {
	rows, err := s.pool.Query(ctx, "SELECT u.id, u.username, u.name, u.avatar_url, m.role, m.created_at FROM space_members m JOIN users u ON u.id = m.user_id WHERE m.space_id = $1 ORDER BY m.created_at ASC", spaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Member
	for rows.Next() {
		var m Member
		if err := rows.Scan(&m.UserID, &m.Username, &m.Name, &m.AvatarURL, &m.Role, &m.JoinedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// AddMember adds a member and stores the space key wrapped for their devices.
// Args: ctx, spaceID, actorID (owner performing the invite), memberID, role,
// keys (wrapped for the invitee's devices + recovery key), expectedEpoch
// Returns: error
// Handles: already a member (ErrConflict), key rotation racing the invite
// (ErrConflict on epoch mismatch), no usable wrapped key (ErrForbidden)
func (s *Store) AddMember(ctx context.Context, spaceID, actorID, memberID uuid.UUID, role string, keys []DeviceWrappedKey, expectedEpoch int) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		var epoch int
		if err := tx.QueryRow(ctx, "SELECT key_epoch FROM spaces WHERE id = $1 AND deleted_at IS NULL FOR UPDATE", spaceID).Scan(&epoch); err != nil {
			if noRows(err) {
				return ErrNotFound
			}
			return err
		}
		if expectedEpoch != 0 && expectedEpoch != epoch {
			return ErrConflict
		}

		if _, err := tx.Exec(ctx, "INSERT INTO space_members (space_id, user_id, role, invited_by) VALUES ($1, $2, $3, $4)", spaceID, memberID, role, actorID); err != nil {
			if isUniqueViolation(err, "") {
				return ErrConflict
			}
			return err
		}

		inserted, err := insertWrappedKeys(ctx, tx, spaceID, epoch, memberID, actorID, keys)
		if err != nil {
			return err
		}
		if inserted == 0 {
			return ErrForbidden
		}
		return nil
	})
}

// RemoveMember drops a membership and every space key wrapped for that member.
// The caller's client must then rotate the space key — this call cannot make the
// removed member forget the key they already held.
// Args: ctx, spaceID, memberID
// Returns: error (ErrForbidden when targeting the owner, ErrNotFound if absent)
func (s *Store) RemoveMember(ctx context.Context, spaceID, memberID uuid.UUID) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		var role string
		if err := tx.QueryRow(ctx, "SELECT role FROM space_members WHERE space_id = $1 AND user_id = $2", spaceID, memberID).Scan(&role); err != nil {
			if noRows(err) {
				return ErrNotFound
			}
			return err
		}
		if role == RoleOwner {
			return ErrForbidden
		}
		if _, err := tx.Exec(ctx, "DELETE FROM space_keys WHERE space_id = $1 AND user_id = $2", spaceID, memberID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, "DELETE FROM space_members WHERE space_id = $1 AND user_id = $2", spaceID, memberID)
		return err
	})
}

// RotationKey is one recipient's copy of a freshly rotated space key.
type RotationKey struct {
	UserID     uuid.UUID
	DeviceID   *uuid.UUID
	WrappedKey []byte
}

// RotateSpaceKey advances a space to a new key epoch, storing the re-wrapped key
// for everyone who remains. The server verifies only coverage — that every
// remaining member's active devices got a key — never the key material itself.
// Args: ctx, spaceID, actorID, newEpoch (must be current+1), keys
// Returns: error
// Handles: concurrent rotation (ErrConflict), incomplete coverage (ErrConflict —
// rolled back, so a partial rotation can never lock members out)
func (s *Store) RotateSpaceKey(ctx context.Context, spaceID, actorID uuid.UUID, newEpoch int, keys []RotationKey) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		var epoch int
		if err := tx.QueryRow(ctx, "SELECT key_epoch FROM spaces WHERE id = $1 AND deleted_at IS NULL FOR UPDATE", spaceID).Scan(&epoch); err != nil {
			if noRows(err) {
				return ErrNotFound
			}
			return err
		}
		if newEpoch != epoch+1 {
			return ErrConflict
		}

		byMember := map[uuid.UUID][]DeviceWrappedKey{}
		for _, k := range keys {
			byMember[k.UserID] = append(byMember[k.UserID], DeviceWrappedKey{DeviceID: k.DeviceID, WrappedKey: k.WrappedKey})
		}
		for memberID, memberKeys := range byMember {
			if _, err := insertWrappedKeys(ctx, tx, spaceID, newEpoch, memberID, actorID, memberKeys); err != nil {
				return err
			}
		}

		var uncovered int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM space_members m JOIN devices d ON d.user_id = m.user_id AND d.status = 'active' LEFT JOIN space_keys k ON k.space_id = m.space_id AND k.key_epoch = $2 AND k.user_id = m.user_id AND k.device_id = d.id WHERE m.space_id = $1 AND k.id IS NULL", spaceID, newEpoch).Scan(&uncovered); err != nil {
			return err
		}
		if uncovered > 0 {
			return ErrConflict
		}

		if _, err := tx.Exec(ctx, "UPDATE spaces SET key_epoch = $2 WHERE id = $1", spaceID, newEpoch); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, "DELETE FROM space_keys WHERE space_id = $1 AND key_epoch < $2", spaceID, newEpoch)
		return err
	})
}

// PendingKeySpaces lists spaces where a device still lacks a wrapped key, letting
// an approving device know exactly what to wrap.
func (s *Store) PendingKeySpaces(ctx context.Context, userID, deviceID uuid.UUID) ([]SpaceMeta, error) {
	rows, err := s.pool.Query(ctx, "SELECT s.id, s.key_epoch, s.head_seq, s.oldest_seq FROM space_members m JOIN spaces s ON s.id = m.space_id AND s.deleted_at IS NULL LEFT JOIN space_keys k ON k.space_id = s.id AND k.key_epoch = s.key_epoch AND k.device_id = $2 WHERE m.user_id = $1 AND k.id IS NULL ORDER BY s.created_at ASC", userID, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []SpaceMeta
	for rows.Next() {
		var m SpaceMeta
		if err := rows.Scan(&m.ID, &m.KeyEpoch, &m.HeadSeq, &m.OldestSeq); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// EscrowWrap is one space's key sealed to a member's account escrow key — the
// copy the server holds so a person who has lost every device can get back in.
type EscrowWrap struct {
	SpaceID    uuid.UUID
	KeyEpoch   int
	WrappedKey []byte
}

// ListEscrowWraps returns every space key wrapped to the user's escrow key at
// the current epoch.
//
// These never leave the server. They are read only to be re-wrapped for a device
// that has just proved the account's email address, which is the one moment the
// escrow key is used at all.
// Args: ctx, userID
// Returns: one wrap per space that has one, oldest space first
func (s *Store) ListEscrowWraps(ctx context.Context, userID uuid.UUID) ([]EscrowWrap, error) {
	rows, err := s.pool.Query(ctx, "SELECT s.id, s.key_epoch, k.wrapped_key FROM space_members m JOIN spaces s ON s.id = m.space_id AND s.deleted_at IS NULL JOIN space_keys k ON k.space_id = s.id AND k.key_epoch = s.key_epoch AND k.user_id = m.user_id AND k.device_id IS NULL WHERE m.user_id = $1 ORDER BY s.created_at ASC", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []EscrowWrap
	for rows.Next() {
		var w EscrowWrap
		if err := rows.Scan(&w.SpaceID, &w.KeyEpoch, &w.WrappedKey); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}
