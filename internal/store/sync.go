package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// MaxChangesPerBatch bounds one append request.
const MaxChangesPerBatch = 100

// MaxChangesPerPage bounds one catch-up page.
const MaxChangesPerPage = 200

// Change is one sealed change-set. Ciphertext is opaque: nothing in this package
// inspects, indexes, or filters on it.
type Change struct {
	Seq            int64
	CID            uuid.UUID
	KeyEpoch       int
	AuthorDeviceID uuid.UUID
	Ciphertext     []byte
	CreatedAt      time.Time
}

// PendingChange is a client-supplied change awaiting a sequence number.
type PendingChange struct {
	CID        uuid.UUID
	Ciphertext []byte
}

// AssignedChange maps a client change id to the sequence number the server gave it.
type AssignedChange struct {
	CID uuid.UUID
	Seq int64
}

// AppendChanges appends sealed changes to a space's log and returns the sequence
// number assigned to each. Sequence allocation is a single atomic increment of
// spaces.head_seq, which is safe under PgBouncer transaction pooling (no session
// state, no advisory locks) and gap-free under concurrent writers.
// Args: ctx, spaceID, keyEpoch (client's epoch), deviceID (author), changes
// Returns: assignments (cid -> seq), new head, error
// Handles: stale key epoch (ErrConflict — client must re-fetch its wrapped key and
// re-encrypt), retried batches (idempotent via the unique cid, original seq
// returned), empty batch
func (s *Store) AppendChanges(ctx context.Context, spaceID uuid.UUID, keyEpoch int, deviceID uuid.UUID, changes []PendingChange) ([]AssignedChange, int64, error) {
	if len(changes) == 0 {
		meta, err := s.SpaceMeta(ctx, spaceID)
		if err != nil {
			return nil, 0, err
		}
		if meta.KeyEpoch != keyEpoch {
			return nil, 0, ErrConflict
		}
		return nil, meta.HeadSeq, nil
	}

	var (
		assigned []AssignedChange
		head     int64
	)
	err := s.tx(ctx, func(tx pgx.Tx) error {
		var epoch int
		if err := tx.QueryRow(ctx, "UPDATE spaces SET head_seq = head_seq + $2 WHERE id = $1 AND deleted_at IS NULL RETURNING head_seq, key_epoch", spaceID, int64(len(changes))).Scan(&head, &epoch); err != nil {
			if noRows(err) {
				return ErrNotFound
			}
			return err
		}
		if epoch != keyEpoch {
			return ErrConflict
		}

		firstSeq := head - int64(len(changes)) + 1

		// One batch, one round trip. RETURNING seq tells us which rows were new;
		// a conflict means this cid was already accepted, so the retry must be
		// answered with the sequence number it got the first time.
		insert := &pgx.Batch{}
		for i, c := range changes {
			insert.Queue("INSERT INTO space_changes (space_id, seq, cid, key_epoch, author_device_id, ciphertext) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (space_id, cid) DO NOTHING RETURNING seq", spaceID, firstSeq+int64(i), c.CID, keyEpoch, deviceID, c.Ciphertext)
		}

		results := tx.SendBatch(ctx, insert)
		assigned = make([]AssignedChange, len(changes))
		var duplicates []int
		for i, c := range changes {
			var seq int64
			switch err := results.QueryRow().Scan(&seq); {
			case err == nil:
				assigned[i] = AssignedChange{CID: c.CID, Seq: seq}
			case noRows(err):
				duplicates = append(duplicates, i)
			default:
				results.Close()
				return err
			}
		}
		if err := results.Close(); err != nil {
			return err
		}

		if len(duplicates) > 0 {
			lookup := &pgx.Batch{}
			for _, i := range duplicates {
				lookup.Queue("SELECT seq FROM space_changes WHERE space_id = $1 AND cid = $2", spaceID, changes[i].CID)
			}
			existing := tx.SendBatch(ctx, lookup)
			for _, i := range duplicates {
				var seq int64
				if err := existing.QueryRow().Scan(&seq); err != nil {
					existing.Close()
					return err
				}
				assigned[i] = AssignedChange{CID: changes[i].CID, Seq: seq}
			}
			if err := existing.Close(); err != nil {
				return err
			}
		}
		return nil
	})
	return assigned, head, err
}

// ChangePage is one catch-up response worth of sealed changes.
type ChangePage struct {
	Changes          []Change
	Head             int64
	OldestSeq        int64
	KeyEpoch         int
	WorkspaceVersion int64
	NeedsResync      bool
}

// GetChanges returns changes after a cursor, or signals that the cursor predates
// compaction and the client must reload the snapshot first.
// Args: ctx, spaceID, since (last seq the client holds), limit
// Returns: page (NeedsResync set when since < oldest retained seq), error
// Handles: caller already at head (empty page, one indexed read), compaction gap
func (s *Store) GetChanges(ctx context.Context, spaceID uuid.UUID, since int64, limit int) (*ChangePage, error) {
	if limit <= 0 || limit > MaxChangesPerPage {
		limit = MaxChangesPerPage
	}

	page := &ChangePage{}
	if err := s.pool.QueryRow(ctx, "SELECT s.head_seq, s.oldest_seq, s.key_epoch, COALESCE(w.version, 0) FROM spaces s LEFT JOIN workspace_docs w ON w.space_id = s.id WHERE s.id = $1 AND s.deleted_at IS NULL", spaceID).Scan(&page.Head, &page.OldestSeq, &page.KeyEpoch, &page.WorkspaceVersion); err != nil {
		if noRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	if since+1 < page.OldestSeq {
		page.NeedsResync = true
		return page, nil
	}
	if since >= page.Head {
		return page, nil
	}

	rows, err := s.pool.Query(ctx, "SELECT seq, cid, key_epoch, author_device_id, ciphertext, created_at FROM space_changes WHERE space_id = $1 AND seq > $2 ORDER BY seq ASC LIMIT $3", spaceID, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var c Change
		if err := rows.Scan(&c.Seq, &c.CID, &c.KeyEpoch, &c.AuthorDeviceID, &c.Ciphertext, &c.CreatedAt); err != nil {
			return nil, err
		}
		page.Changes = append(page.Changes, c)
	}
	return page, rows.Err()
}

// Snapshot is a compacted, sealed representation of a space up to a sequence
// number. Small snapshots live inline in Neon; large ones live in Vercel Blob and
// the row keeps only an opaque pointer.
type Snapshot struct {
	SpaceID    uuid.UUID
	UptoSeq    int64
	KeyEpoch   int
	Storage    string
	Ciphertext []byte
	BlobURL    *string
	SizeBucket int
	CreatedAt  time.Time
}

// PutSnapshot stores a compacted snapshot and truncates the change log up to
// uptoSeq, advancing oldest_seq so lagging clients are told to resync.
// Args: ctx, spaceID, deviceID, snapshot fields (storage "inline" or "blob")
// Returns: previous blob URL (nil if none) for best-effort cleanup, error
// Handles: snapshot behind the stored one or ahead of head (ErrConflict), stale
// key epoch (ErrConflict)
func (s *Store) PutSnapshot(ctx context.Context, spaceID, deviceID uuid.UUID, uptoSeq int64, keyEpoch int, storage string, ciphertext []byte, blobURL *string, sizeBucket int) (*string, error) {
	var staleBlob *string
	err := s.tx(ctx, func(tx pgx.Tx) error {
		var (
			head  int64
			epoch int
		)
		if err := tx.QueryRow(ctx, "SELECT head_seq, key_epoch FROM spaces WHERE id = $1 AND deleted_at IS NULL FOR UPDATE", spaceID).Scan(&head, &epoch); err != nil {
			if noRows(err) {
				return ErrNotFound
			}
			return err
		}
		if epoch != keyEpoch {
			return ErrConflict
		}
		if uptoSeq > head || uptoSeq < 0 {
			return ErrConflict
		}

		var existingUpto int64
		err := tx.QueryRow(ctx, "SELECT upto_seq, blob_url FROM space_snapshots WHERE space_id = $1", spaceID).Scan(&existingUpto, &staleBlob)
		if err != nil && !noRows(err) {
			return err
		}
		if err == nil && uptoSeq <= existingUpto {
			return ErrConflict
		}

		if _, err := tx.Exec(ctx, "INSERT INTO space_snapshots (space_id, upto_seq, key_epoch, storage, ciphertext, blob_url, size_bucket, created_by_device) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (space_id) DO UPDATE SET upto_seq = EXCLUDED.upto_seq, key_epoch = EXCLUDED.key_epoch, storage = EXCLUDED.storage, ciphertext = EXCLUDED.ciphertext, blob_url = EXCLUDED.blob_url, size_bucket = EXCLUDED.size_bucket, created_by_device = EXCLUDED.created_by_device, created_at = now()", spaceID, uptoSeq, keyEpoch, storage, ciphertext, blobURL, sizeBucket, deviceID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "UPDATE spaces SET oldest_seq = $2 WHERE id = $1", spaceID, uptoSeq+1); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, "DELETE FROM space_changes WHERE space_id = $1 AND seq <= $2", spaceID, uptoSeq)
		return err
	})
	if err != nil {
		return nil, err
	}
	return staleBlob, nil
}

func (s *Store) GetSnapshot(ctx context.Context, spaceID uuid.UUID) (*Snapshot, error) {
	var snap Snapshot
	err := s.pool.QueryRow(ctx, "SELECT space_id, upto_seq, key_epoch, storage, ciphertext, blob_url, size_bucket, created_at FROM space_snapshots WHERE space_id = $1", spaceID).Scan(&snap.SpaceID, &snap.UptoSeq, &snap.KeyEpoch, &snap.Storage, &snap.Ciphertext, &snap.BlobURL, &snap.SizeBucket, &snap.CreatedAt)
	if err != nil {
		if noRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &snap, nil
}

// WorkspaceDoc is the Tier 1 blob: page tree, titles, tags, pins — all sealed.
type WorkspaceDoc struct {
	SpaceID    uuid.UUID
	Version    int64
	KeyEpoch   int
	Ciphertext []byte
	UpdatedAt  time.Time
}

func (s *Store) GetWorkspaceDoc(ctx context.Context, spaceID uuid.UUID) (*WorkspaceDoc, error) {
	var doc WorkspaceDoc
	err := s.pool.QueryRow(ctx, "SELECT space_id, version, key_epoch, ciphertext, updated_at FROM workspace_docs WHERE space_id = $1", spaceID).Scan(&doc.SpaceID, &doc.Version, &doc.KeyEpoch, &doc.Ciphertext, &doc.UpdatedAt)
	if err != nil {
		if noRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &doc, nil
}

// PutWorkspaceDoc replaces the sealed workspace document under optimistic
// concurrency control.
// Args: ctx, spaceID, deviceID, baseVersion (0 to create), keyEpoch, ciphertext
// Returns: new version, error
// Handles: lost update (ErrConflict — the client merges locally and retries),
// stale key epoch (ErrConflict)
func (s *Store) PutWorkspaceDoc(ctx context.Context, spaceID, deviceID uuid.UUID, baseVersion int64, keyEpoch int, ciphertext []byte) (int64, error) {
	var version int64
	err := s.tx(ctx, func(tx pgx.Tx) error {
		var epoch int
		if err := tx.QueryRow(ctx, "SELECT key_epoch FROM spaces WHERE id = $1 AND deleted_at IS NULL", spaceID).Scan(&epoch); err != nil {
			if noRows(err) {
				return ErrNotFound
			}
			return err
		}
		if epoch != keyEpoch {
			return ErrConflict
		}

		err := tx.QueryRow(ctx, "INSERT INTO workspace_docs (space_id, version, key_epoch, ciphertext, updated_by_device) VALUES ($1, 1, $2, $3, $4) ON CONFLICT (space_id) DO UPDATE SET version = workspace_docs.version + 1, key_epoch = EXCLUDED.key_epoch, ciphertext = EXCLUDED.ciphertext, updated_by_device = EXCLUDED.updated_by_device, updated_at = now() WHERE workspace_docs.version = $5 RETURNING version", spaceID, keyEpoch, ciphertext, deviceID, baseVersion).Scan(&version)
		if err != nil {
			if noRows(err) {
				return ErrConflict
			}
			return err
		}
		return nil
	})
	return version, err
}
