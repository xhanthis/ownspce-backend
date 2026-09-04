package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	DeviceStatusPending = "pending"
	DeviceStatusActive  = "active"
	DeviceStatusRevoked = "revoked"

	// DevicePlatformWeb is the only platform that gets the short session window;
	// see refreshTTLFor.
	DevicePlatformWeb = "web"

	// How a device came to be trusted. Recorded because the answer changes what
	// a member should think before handing it a space key: a device let in by
	// email proved control of an inbox and nothing more.
	ApprovedViaFirst    = "first"
	ApprovedViaDevice   = "device"
	ApprovedViaRecovery = "recovery"
	ApprovedViaEmail    = "email"
)

// Device holds a device's Tier 0 record. PublicKey is an X25519 public key; the
// matching private key never reaches the server.
type Device struct {
	ID          uuid.UUID
	UserID      uuid.UUID
	Label       string
	Platform    string
	PublicKey   []byte
	Status      string
	ApprovedVia *string
	CreatedAt   time.Time
	LastSeenAt  *time.Time
}

const deviceColumns = `id, user_id, label, platform, public_key, status, approved_via, created_at, last_seen_at`

func scanDevice(row pgx.Row) (*Device, error) {
	var d Device
	if err := row.Scan(&d.ID, &d.UserID, &d.Label, &d.Platform, &d.PublicKey, &d.Status, &d.ApprovedVia, &d.CreatedAt, &d.LastSeenAt); err != nil {
		if noRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &d, nil
}

// RegisterDevice adds a device for a user. The first live device of an account is
// trusted automatically; every later one lands pending until an existing device
// approves it or the recovery phrase provisions it.
// Args: ctx, userID, label, platform, publicKey (32B X25519)
// Returns: device (existing row if this public key is already registered), error
// Handles: repeat registration of the same key (idempotent), first-device bootstrap
func (s *Store) RegisterDevice(ctx context.Context, userID uuid.UUID, label, platform string, publicKey []byte) (*Device, error) {
	var device *Device
	err := s.tx(ctx, func(tx pgx.Tx) error {
		existing, err := scanDevice(tx.QueryRow(ctx, "SELECT "+deviceColumns+" FROM devices WHERE user_id = $1 AND public_key = $2 AND status <> 'revoked'", userID, publicKey))
		if err == nil {
			device = existing
			return nil
		}
		if !errors.Is(err, ErrNotFound) {
			return err
		}

		var liveCount int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM devices WHERE user_id = $1 AND status <> 'revoked'", userID).Scan(&liveCount); err != nil {
			return err
		}
		status := DeviceStatusPending
		var via *string
		if liveCount == 0 {
			status = DeviceStatusActive
			first := ApprovedViaFirst
			via = &first
		}

		device, err = scanDevice(tx.QueryRow(ctx, "INSERT INTO devices (user_id, label, platform, public_key, status, approved_via) VALUES ($1, $2, $3, $4, $5, $6) RETURNING "+deviceColumns, userID, label, platform, publicKey, status, via))
		return err
	})
	return device, err
}

// LiveDevice loads a device only if it is not revoked, giving the auth middleware
// its per-request revocation check.
func (s *Store) LiveDevice(ctx context.Context, id uuid.UUID) (*Device, error) {
	return scanDevice(s.pool.QueryRow(ctx, "SELECT "+deviceColumns+" FROM devices WHERE id = $1 AND status <> 'revoked'", id))
}

func (s *Store) ListDevices(ctx context.Context, userID uuid.UUID) ([]Device, error) {
	rows, err := s.pool.Query(ctx, "SELECT "+deviceColumns+" FROM devices WHERE user_id = $1 AND status <> 'revoked' ORDER BY created_at ASC", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Device
	for rows.Next() {
		var d Device
		if err := rows.Scan(&d.ID, &d.UserID, &d.Label, &d.Platform, &d.PublicKey, &d.Status, &d.ApprovedVia, &d.CreatedAt, &d.LastSeenAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// TouchDevice records liveness; called on refresh only so the sync poll stays a
// read-only path.
func (s *Store) TouchDevice(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, "UPDATE devices SET last_seen_at = now() WHERE id = $1", id)
	return err
}

// CountDeviceKeys reports how many space keys are filed for a device, which is
// how the sign-in path tells an active device that can read something from one
// that got in but holds nothing.
func (s *Store) CountDeviceKeys(ctx context.Context, deviceID uuid.UUID) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx, "SELECT count(*) FROM space_keys WHERE device_id = $1", deviceID).Scan(&count)
	return count, err
}

// WrappedSpaceKey is a space key sealed to one recipient public key. The server
// stores it and can never unwrap it.
type WrappedSpaceKey struct {
	SpaceID    uuid.UUID
	KeyEpoch   int
	WrappedKey []byte
}

// ApproveDevice activates a pending device and stores the space keys wrapped to
// its public key, in one transaction.
// Args: ctx, userID, deviceID (the pending device), approverDeviceID (nil for the
// recovery-phrase and email paths), via (how it was let in), keys (wrapped space
// keys)
// Returns: activated device, error
// Handles: device not found or owned by another user (ErrNotFound), already-active
// device (idempotent), keys for spaces the user no longer belongs to or whose
// epoch has since rotated (silently skipped so the client retries with fresh keys)
func (s *Store) ApproveDevice(ctx context.Context, userID, deviceID uuid.UUID, approverDeviceID *uuid.UUID, via string, keys []WrappedSpaceKey) (*Device, error) {
	var device *Device
	err := s.tx(ctx, func(tx pgx.Tx) error {
		d, err := scanDevice(tx.QueryRow(ctx, "SELECT "+deviceColumns+" FROM devices WHERE id = $1 AND user_id = $2 AND status <> 'revoked' FOR UPDATE", deviceID, userID))
		if err != nil {
			return err
		}

		if len(keys) > 0 {
			batch := &pgx.Batch{}
			for _, k := range keys {
				batch.Queue("INSERT INTO space_keys (space_id, user_id, device_id, key_epoch, wrapped_key, created_by) SELECT s.id, $1, $2, s.key_epoch, $3, $1 FROM spaces s JOIN space_members m ON m.space_id = s.id AND m.user_id = $1 WHERE s.id = $4 AND s.key_epoch = $5 AND s.deleted_at IS NULL ON CONFLICT DO NOTHING", userID, deviceID, k.WrappedKey, k.SpaceID, k.KeyEpoch)
			}
			results := tx.SendBatch(ctx, batch)
			for range keys {
				if _, err := results.Exec(); err != nil {
					results.Close()
					return err
				}
			}
			if err := results.Close(); err != nil {
				return err
			}
		}

		device, err = scanDevice(tx.QueryRow(ctx, "UPDATE devices SET status = 'active', approved_by_device = COALESCE($2, approved_by_device), approved_via = COALESCE(approved_via, $3) WHERE id = $1 RETURNING "+deviceColumns, d.ID, approverDeviceID, via))
		return err
	})
	return device, err
}

// RevokeDevice marks a device revoked, kills its refresh tokens, and drops the
// space keys wrapped to it. Access dies on the device's very next request because
// the auth middleware re-checks device status every time.
// Args: ctx, userID, deviceID
// Returns: error (ErrNotFound when the device is absent or owned by someone else)
// Handles: already revoked (no-op success)
func (s *Store) RevokeDevice(ctx context.Context, userID, deviceID uuid.UUID) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, "UPDATE devices SET status = 'revoked', revoked_at = now() WHERE id = $1 AND user_id = $2 AND status <> 'revoked'", deviceID, userID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			var exists bool
			if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM devices WHERE id = $1 AND user_id = $2)", deviceID, userID).Scan(&exists); err != nil {
				return err
			}
			if !exists {
				return ErrNotFound
			}
			return nil
		}
		if _, err := tx.Exec(ctx, "UPDATE refresh_tokens SET revoked_at = now() WHERE device_id = $1 AND revoked_at IS NULL", deviceID); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, "DELETE FROM space_keys WHERE device_id = $1", deviceID)
		return err
	})
}

// KeyDirectory is the public half of a user's encryption identity: the per-device
// X25519 public keys an inviter wraps a space key for, plus the recovery public key.
type KeyDirectory struct {
	UserID          uuid.UUID
	Devices         []Device
	EscrowPublicKey []byte
}

// PublicKeyDirectory returns a user's active device public keys and recovery key.
// Args: ctx, userID
// Returns: directory (active devices only), error (ErrNotFound for unknown user)
func (s *Store) PublicKeyDirectory(ctx context.Context, userID uuid.UUID) (*KeyDirectory, error) {
	dir := &KeyDirectory{UserID: userID}
	if err := s.pool.QueryRow(ctx, "SELECT escrow_public_key FROM users WHERE id = $1", userID).Scan(&dir.EscrowPublicKey); err != nil {
		if noRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	rows, err := s.pool.Query(ctx, "SELECT id, public_key FROM devices WHERE user_id = $1 AND status = 'active' ORDER BY created_at ASC", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var d Device
		if err := rows.Scan(&d.ID, &d.PublicKey); err != nil {
			return nil, err
		}
		dir.Devices = append(dir.Devices, d)
	}
	return dir, rows.Err()
}
