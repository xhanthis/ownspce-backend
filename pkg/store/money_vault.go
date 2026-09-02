package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// The Kosh ledger is sealed, like everything else in this database.
//
// An earlier draft of money stored amounts, categories and notes in the clear so
// the server could add them up. That bought server-side budgets and settle-up
// and cost the household the guarantee the rest of the product makes. It is gone.
// The tables below hold one ciphertext per record and the few plaintext columns
// a query genuinely cannot do without: the space the row belongs to, the calendar
// date an entry happened on (a ledger is read by period, and a server that cannot
// filter by date has to ship every row a household ever wrote), a stable client
// id for idempotent upserts, and the key epoch that says which space key opens it.
//
// Arithmetic moved to the client, where money-core already lived. Budgets,
// category splits, settle-up and portfolio valuation are computed over decrypted
// rows on the device, and the server never learns an amount.

// MoneyObjectKinds are the record kinds money_objects holds. Entries — the
// ledger itself — live in their own table because they are the only money record
// queried by date range.
var MoneyObjectKinds = map[string]bool{
	"category": true,
	"account":  true,
	"budget":   true,
	"bill":     true,
	"holding":  true,
}

// MoneyVault is a household: a space with a sealed settings document. Its
// existence is the flag that money is enabled — a space with no vault row is a
// plain notes workspace and never appears in the household list.
type MoneyVault struct {
	SpaceID    uuid.UUID
	KeyEpoch   int
	Version    int64
	Ciphertext []byte
	UpdatedAt  time.Time
}

// MoneyHouseholdSummary is one household as the calling device sees it, carrying
// the space key wrapped for that device so it can start decrypting immediately.
// A nil WrappedKey means this device is not approved for the household yet.
type MoneyHouseholdSummary struct {
	SpaceID      uuid.UUID
	Role         string
	KeyEpoch     int
	MemberCount  int
	VaultVersion int64
	WrappedKey   []byte
}

// MoneyEntry is one sealed ledger row.
type MoneyEntry struct {
	ID         uuid.UUID
	ClientID   uuid.UUID
	OccurredOn time.Time
	KeyEpoch   int
	Ciphertext []byte
	CreatedBy  *uuid.UUID
	UpdatedAt  time.Time
}

// MoneyObject is one sealed non-ledger record: a category, account, budget, bill
// or holding.
type MoneyObject struct {
	ID         uuid.UUID
	Kind       string
	ClientID   uuid.UUID
	SortOrder  int
	KeyEpoch   int
	Ciphertext []byte
	UpdatedAt  time.Time
}

// MoneyKeyGap is one recipient inside a household that has no wrapped space key
// at the current epoch: an active device, or a member's account recovery key.
// The owner's client wraps the space key to PublicKey and files it back.
type MoneyKeyGap struct {
	UserID    uuid.UUID
	DeviceID  *uuid.UUID
	PublicKey []byte
	Name      string
	Username  *string
}

// SealedRecord is one record on its way into the database. The server treats
// Ciphertext as opaque bytes: it is length-checked against a padding bucket by
// the HTTP layer and never parsed.
type SealedRecord struct {
	ClientID   uuid.UUID
	Kind       string
	OccurredOn time.Time
	SortOrder  int
	Ciphertext []byte
}

const moneyEntryColumns = `id, client_id, occurred_on, key_epoch, ciphertext, created_by, updated_at`

const moneyObjectColumns = `id, kind, client_id, sort_order, key_epoch, ciphertext, updated_at`

// CreateMoneyHousehold creates a household: a space, its owner membership, the
// space key wrapped for the owner's devices, and the sealed vault document.
//
// It is one transaction on purpose. A space whose key nobody holds is
// unopenable, and a space with no vault is invisible to the money surface — both
// are states a partial failure could otherwise leave behind permanently.
// The id is supplied by the client, not generated here. The household's sealed
// settings document binds that id into its authenticated data, so the client has
// to know it before it can seal anything — and a server-generated id would mean
// sealing twice, once against a placeholder.
// Args: ctx, spaceID (client-minted), ownerID, keys (wrapped space keys;
// DeviceID nil means a recovery wrap), ciphertext (the sealed settings document)
// Returns: error
// Handles: keys naming devices that are not the owner's active devices (skipped
// by insertWrappedKeys), and zero usable keys, which rolls the whole thing back
// with ErrForbidden rather than creating a household nobody can read; an id that
// already exists, which is ErrConflict rather than a leaked constraint error
func (s *Store) CreateMoneyHousehold(ctx context.Context, spaceID, ownerID uuid.UUID, keys []DeviceWrappedKey, ciphertext []byte) error {
	err := s.tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "INSERT INTO spaces (id, owner_id) VALUES ($1, $2)", spaceID, ownerID); err != nil {
			if isUniqueViolation(err, "") {
				return ErrConflict
			}
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
		_, err = tx.Exec(ctx, "INSERT INTO money_vaults (space_id, key_epoch, ciphertext, created_by) VALUES ($1, 1, $2, $3)", spaceID, ciphertext, ownerID)
		return err
	})
	return err
}

// EnableMoney adds a vault to an existing space, turning a notes workspace into
// a household without minting a second space or a second membership list.
// Args: ctx, spaceID, actorID, keyEpoch (the space's current epoch, which the
// caller sealed against), ciphertext
// Returns: the vault, ErrConflict when money is already enabled here
func (s *Store) EnableMoney(ctx context.Context, spaceID, actorID uuid.UUID, keyEpoch int, ciphertext []byte) (*MoneyVault, error) {
	row := s.pool.QueryRow(ctx, "INSERT INTO money_vaults (space_id, key_epoch, ciphertext, created_by) SELECT $1, $2, $3, $4 WHERE EXISTS (SELECT 1 FROM spaces WHERE id = $1 AND deleted_at IS NULL AND key_epoch = $2) ON CONFLICT (space_id) DO NOTHING RETURNING space_id, key_epoch, version, ciphertext, updated_at", spaceID, keyEpoch, ciphertext, actorID)
	vault, err := scanMoneyVault(row)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrConflict
	}
	return vault, err
}

// MoneyVaultFor reads a household's sealed settings document.
// Args: ctx, spaceID
// Returns: the vault, ErrNotFound when money is not enabled on the space
func (s *Store) MoneyVaultFor(ctx context.Context, spaceID uuid.UUID) (*MoneyVault, error) {
	return scanMoneyVault(s.pool.QueryRow(ctx, "SELECT space_id, key_epoch, version, ciphertext, updated_at FROM money_vaults WHERE space_id = $1", spaceID))
}

// PutMoneyVault replaces the sealed settings document under optimistic
// concurrency, so two members editing household rules at once cannot silently
// overwrite each other — the loser gets a conflict and re-reads.
// Args: ctx, spaceID, expectedVersion, keyEpoch, ciphertext
// Returns: the stored vault, ErrConflict when the version moved on, ErrNotFound
// when money is not enabled here
func (s *Store) PutMoneyVault(ctx context.Context, spaceID uuid.UUID, expectedVersion int64, keyEpoch int, ciphertext []byte) (*MoneyVault, error) {
	vault, err := scanMoneyVault(s.pool.QueryRow(ctx, "UPDATE money_vaults SET ciphertext = $3, key_epoch = $4, version = version + 1, updated_at = now() WHERE space_id = $1 AND version = $2 RETURNING space_id, key_epoch, version, ciphertext, updated_at", spaceID, expectedVersion, ciphertext, keyEpoch))
	if errors.Is(err, ErrNotFound) {
		var exists bool
		if probe := s.pool.QueryRow(ctx, "SELECT true FROM money_vaults WHERE space_id = $1", spaceID).Scan(&exists); probe == nil {
			return nil, ErrConflict
		}
		return nil, ErrNotFound
	}
	return vault, err
}

// ListMoneyHouseholds returns every household the user belongs to, each with the
// space key wrapped for the calling device.
// Args: ctx, userID, deviceID (the device asking)
// Returns: households oldest first, error
// Handles: a household this device is not yet approved for, which comes back
// with a nil WrappedKey rather than being hidden — the client shows it as
// awaiting approval instead of pretending it does not exist
func (s *Store) ListMoneyHouseholds(ctx context.Context, userID, deviceID uuid.UUID) ([]MoneyHouseholdSummary, error) {
	rows, err := s.pool.Query(ctx, "SELECT sp.id, m.role, sp.key_epoch, (SELECT count(*) FROM space_members c WHERE c.space_id = sp.id), v.version, k.wrapped_key FROM space_members m JOIN spaces sp ON sp.id = m.space_id AND sp.deleted_at IS NULL JOIN money_vaults v ON v.space_id = sp.id LEFT JOIN space_keys k ON k.space_id = sp.id AND k.key_epoch = sp.key_epoch AND k.user_id = m.user_id AND k.device_id = $2 WHERE m.user_id = $1 ORDER BY sp.created_at ASC", userID, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []MoneyHouseholdSummary
	for rows.Next() {
		var h MoneyHouseholdSummary
		if err := rows.Scan(&h.SpaceID, &h.Role, &h.KeyEpoch, &h.MemberCount, &h.VaultVersion, &h.WrappedKey); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// MoneyRole resolves the caller's role in a household, and doubles as the check
// that money is enabled there: a space with no vault answers ErrNotFound whether
// or not the caller is a member of it.
// Args: ctx, spaceID, userID
// Returns: role, ErrNotFound when the space has no vault or the user no membership
func (s *Store) MoneyRole(ctx context.Context, spaceID, userID uuid.UUID) (string, error) {
	var role string
	err := s.pool.QueryRow(ctx, "SELECT m.role FROM space_members m JOIN spaces sp ON sp.id = m.space_id AND sp.deleted_at IS NULL JOIN money_vaults v ON v.space_id = sp.id WHERE m.space_id = $1 AND m.user_id = $2", spaceID, userID).Scan(&role)
	if err != nil {
		if noRows(err) {
			return "", ErrNotFound
		}
		return "", err
	}
	return role, nil
}

// MoneyEntryFilter bounds one page of the ledger.
type MoneyEntryFilter struct {
	SpaceID uuid.UUID
	From    time.Time
	To      time.Time
	Limit   int
	// Cursor is the opaque "date|id" position returned by the previous page.
	CursorDate time.Time
	CursorID   uuid.UUID
	HasCursor  bool
}

// ListMoneyEntries returns one page of sealed ledger rows, newest first.
//
// Keyset pagination on (occurred_on DESC, id DESC) rather than an offset: a
// household logging entries while someone scrolls would otherwise see rows
// repeat or vanish between pages.
// Args: ctx, filter
// Returns: entries, the cursor for the next page ("" when the last page), error
func (s *Store) ListMoneyEntries(ctx context.Context, f MoneyEntryFilter) ([]MoneyEntry, string, error) {
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 200
	}

	query := "SELECT " + moneyEntryColumns + " FROM money_entries WHERE space_id = $1 AND deleted_at IS NULL AND occurred_on >= $2 AND occurred_on <= $3"
	args := []any{f.SpaceID, f.From, f.To}
	if f.HasCursor {
		query += " AND (occurred_on, id) < ($4, $5) ORDER BY occurred_on DESC, id DESC LIMIT $6"
		args = append(args, f.CursorDate, f.CursorID, limit+1)
	} else {
		query += " ORDER BY occurred_on DESC, id DESC LIMIT $4"
		args = append(args, limit+1)
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()

	var out []MoneyEntry
	for rows.Next() {
		var e MoneyEntry
		if err := rows.Scan(&e.ID, &e.ClientID, &e.OccurredOn, &e.KeyEpoch, &e.Ciphertext, &e.CreatedBy, &e.UpdatedAt); err != nil {
			return nil, "", err
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}

	next := ""
	if len(out) > limit {
		last := out[limit-1]
		next = last.OccurredOn.UTC().Format("2006-01-02") + "|" + last.ID.String()
		out = out[:limit]
	}
	return out, next, nil
}

// PutMoneyEntries upserts a batch of sealed ledger rows, keyed by client id.
//
// Upsert rather than insert because the client mints the id before the request
// leaves the device: a retry after a dropped response then updates the row it
// already created instead of logging the same dinner twice. The whole batch is
// one transaction, so a CSV import either lands or does not.
// Args: ctx, spaceID, actorID, records (client id, occurred-on date, ciphertext)
// Returns: the stored rows, error
func (s *Store) PutMoneyEntries(ctx context.Context, spaceID, actorID uuid.UUID, records []SealedRecord) ([]MoneyEntry, error) {
	if len(records) == 0 {
		return nil, nil
	}

	out := make([]MoneyEntry, 0, len(records))
	err := s.tx(ctx, func(tx pgx.Tx) error {
		epoch, err := currentEpoch(ctx, tx, spaceID)
		if err != nil {
			return err
		}

		batch := &pgx.Batch{}
		for _, rec := range records {
			batch.Queue("INSERT INTO money_entries (space_id, client_id, occurred_on, key_epoch, ciphertext, created_by, updated_by) VALUES ($1, $2, $3, $4, $5, $6, $6) ON CONFLICT (space_id, client_id) DO UPDATE SET occurred_on = EXCLUDED.occurred_on, key_epoch = EXCLUDED.key_epoch, ciphertext = EXCLUDED.ciphertext, updated_by = EXCLUDED.updated_by, updated_at = now(), deleted_at = NULL RETURNING "+moneyEntryColumns, spaceID, rec.ClientID, rec.OccurredOn, epoch, rec.Ciphertext, actorID)
		}

		results := tx.SendBatch(ctx, batch)
		for range records {
			var e MoneyEntry
			if err := results.QueryRow().Scan(&e.ID, &e.ClientID, &e.OccurredOn, &e.KeyEpoch, &e.Ciphertext, &e.CreatedBy, &e.UpdatedAt); err != nil {
				_ = results.Close()
				return err
			}
			out = append(out, e)
		}
		return results.Close()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// DeleteMoneyEntry tombstones one ledger row.
//
// A tombstone, not a delete: another member's device may be holding the row and
// needs to learn it went away, and an undo has to have something to restore.
// Args: ctx, spaceID, clientID
// Returns: ErrNotFound when no live row matched
func (s *Store) DeleteMoneyEntry(ctx context.Context, spaceID, clientID uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, "UPDATE money_entries SET deleted_at = now(), updated_at = now() WHERE space_id = $1 AND client_id = $2 AND deleted_at IS NULL", spaceID, clientID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListMoneyObjects returns every live record of one kind, or of all kinds when
// kind is empty.
// Args: ctx, spaceID, kind ("" for all)
// Returns: objects ordered by kind then sort order, error
func (s *Store) ListMoneyObjects(ctx context.Context, spaceID uuid.UUID, kind string) ([]MoneyObject, error) {
	query := "SELECT " + moneyObjectColumns + " FROM money_objects WHERE space_id = $1 AND deleted_at IS NULL"
	args := []any{spaceID}
	if kind != "" {
		query += " AND kind = $2"
		args = append(args, kind)
	}
	query += " ORDER BY kind ASC, sort_order ASC, id ASC"

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []MoneyObject
	for rows.Next() {
		var o MoneyObject
		if err := rows.Scan(&o.ID, &o.Kind, &o.ClientID, &o.SortOrder, &o.KeyEpoch, &o.Ciphertext, &o.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// PutMoneyObjects upserts a batch of sealed non-ledger records, keyed by kind
// and client id. One transaction, for the same reason as PutMoneyEntries.
// Args: ctx, spaceID, actorID, records (kind, client id, sort order, ciphertext)
// Returns: the stored rows, error
func (s *Store) PutMoneyObjects(ctx context.Context, spaceID, actorID uuid.UUID, records []SealedRecord) ([]MoneyObject, error) {
	if len(records) == 0 {
		return nil, nil
	}

	out := make([]MoneyObject, 0, len(records))
	err := s.tx(ctx, func(tx pgx.Tx) error {
		epoch, err := currentEpoch(ctx, tx, spaceID)
		if err != nil {
			return err
		}

		batch := &pgx.Batch{}
		for _, rec := range records {
			batch.Queue("INSERT INTO money_objects (space_id, kind, client_id, sort_order, key_epoch, ciphertext, created_by, updated_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $7) ON CONFLICT (space_id, kind, client_id) DO UPDATE SET sort_order = EXCLUDED.sort_order, key_epoch = EXCLUDED.key_epoch, ciphertext = EXCLUDED.ciphertext, updated_by = EXCLUDED.updated_by, updated_at = now(), deleted_at = NULL RETURNING "+moneyObjectColumns, spaceID, rec.Kind, rec.ClientID, rec.SortOrder, epoch, rec.Ciphertext, actorID)
		}

		results := tx.SendBatch(ctx, batch)
		for range records {
			var o MoneyObject
			if err := results.QueryRow().Scan(&o.ID, &o.Kind, &o.ClientID, &o.SortOrder, &o.KeyEpoch, &o.Ciphertext, &o.UpdatedAt); err != nil {
				_ = results.Close()
				return err
			}
			out = append(out, o)
		}
		return results.Close()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// DeleteMoneyObject tombstones one non-ledger record.
// Args: ctx, spaceID, kind, clientID
// Returns: ErrNotFound when no live row matched
func (s *Store) DeleteMoneyObject(ctx context.Context, spaceID uuid.UUID, kind string, clientID uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, "UPDATE money_objects SET deleted_at = now(), updated_at = now() WHERE space_id = $1 AND kind = $2 AND client_id = $3 AND deleted_at IS NULL", spaceID, kind, clientID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// MoneyKeyGaps lists every recipient in a household that holds no wrapped space
// key at the current epoch.
//
// This is what makes an emailed invite work under end-to-end encryption. The
// invitee accepts and becomes a member, but membership is not a key: somebody
// already holding the space key has to wrap it for their devices. The owner's
// client reads this list, wraps, and files the results back through GrantSpaceKeys.
// A member's own recovery key appears here too, so a household survives the loss
// of every device the invitee owns.
// Args: ctx, spaceID
// Returns: gaps ordered by member then device, error
func (s *Store) MoneyKeyGaps(ctx context.Context, spaceID uuid.UUID) ([]MoneyKeyGap, error) {
	rows, err := s.pool.Query(ctx, "SELECT m.user_id, d.id, d.public_key, u.name, u.username FROM space_members m JOIN spaces sp ON sp.id = m.space_id JOIN users u ON u.id = m.user_id JOIN devices d ON d.user_id = m.user_id AND d.status = 'active' LEFT JOIN space_keys k ON k.space_id = m.space_id AND k.key_epoch = sp.key_epoch AND k.user_id = m.user_id AND k.device_id = d.id WHERE m.space_id = $1 AND k.id IS NULL UNION ALL SELECT m.user_id, NULL, u.recovery_public_key, u.name, u.username FROM space_members m JOIN spaces sp ON sp.id = m.space_id JOIN users u ON u.id = m.user_id LEFT JOIN space_keys k ON k.space_id = m.space_id AND k.key_epoch = sp.key_epoch AND k.user_id = m.user_id AND k.device_id IS NULL WHERE m.space_id = $1 AND u.recovery_public_key IS NOT NULL AND k.id IS NULL ORDER BY 1, 2 NULLS LAST", spaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []MoneyKeyGap
	for rows.Next() {
		var g MoneyKeyGap
		if err := rows.Scan(&g.UserID, &g.DeviceID, &g.PublicKey, &g.Name, &g.Username); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// GrantSpaceKeys files space keys wrapped for members that had none, without
// advancing the epoch.
//
// It is deliberately not RotateSpaceKey: rotation is for taking access away and
// demands complete coverage, while this is for handing access out and must work
// one member at a time as invitations are accepted. Postgres enforces that every
// named device really is an active device of the named member, so a caller
// cannot file a key against somebody else's device.
// Args: ctx, spaceID, actorID, epoch (must be the space's current epoch), keys
// Returns: how many keys landed, ErrConflict when the epoch is stale
func (s *Store) GrantSpaceKeys(ctx context.Context, spaceID, actorID uuid.UUID, epoch int, keys []RotationKey) (int64, error) {
	var granted int64
	err := s.tx(ctx, func(tx pgx.Tx) error {
		current, err := currentEpoch(ctx, tx, spaceID)
		if err != nil {
			return err
		}
		if current != epoch {
			return ErrConflict
		}

		byMember := map[uuid.UUID][]DeviceWrappedKey{}
		for _, k := range keys {
			byMember[k.UserID] = append(byMember[k.UserID], DeviceWrappedKey{DeviceID: k.DeviceID, WrappedKey: k.WrappedKey})
		}
		for memberID, memberKeys := range byMember {
			var isMember bool
			if err := tx.QueryRow(ctx, "SELECT true FROM space_members WHERE space_id = $1 AND user_id = $2", spaceID, memberID).Scan(&isMember); err != nil {
				if noRows(err) {
					return ErrForbidden
				}
				return err
			}
			n, err := insertWrappedKeys(ctx, tx, spaceID, epoch, memberID, actorID, memberKeys)
			if err != nil {
				return err
			}
			granted += n
		}
		return nil
	})
	return granted, err
}

// currentEpoch reads a live space's key epoch inside a transaction.
func currentEpoch(ctx context.Context, tx pgx.Tx, spaceID uuid.UUID) (int, error) {
	var epoch int
	if err := tx.QueryRow(ctx, "SELECT key_epoch FROM spaces WHERE id = $1 AND deleted_at IS NULL", spaceID).Scan(&epoch); err != nil {
		if noRows(err) {
			return 0, ErrNotFound
		}
		return 0, err
	}
	return epoch, nil
}

func scanMoneyVault(row pgx.Row) (*MoneyVault, error) {
	var v MoneyVault
	if err := row.Scan(&v.SpaceID, &v.KeyEpoch, &v.Version, &v.Ciphertext, &v.UpdatedAt); err != nil {
		if noRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &v, nil
}
