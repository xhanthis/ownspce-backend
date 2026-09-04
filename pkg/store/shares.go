package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Share is one published read-only snapshot of a page. The row holds ciphertext
// and a byte count and nothing else: the key that opens it lives in the reader's
// URL fragment, which never reaches this server, so the space it came from can
// never be recovered from this table alone.
type Share struct {
	ID         uuid.UUID
	SpaceID    uuid.UUID
	Ciphertext []byte
	SizeBytes  int64
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// UpsertShare creates or replaces the sealed snapshot behind a share link.
// Args: ctx, shareID (minted by the client, and the capability in the link),
// spaceID, ciphertext
// Returns: error
// Handles: re-publishing an existing share, which overwrites the bytes in place
// so the link a reader already holds keeps working; a share id that belongs to
// another space is rejected rather than silently rebound (ErrForbidden), since
// binding it would let one space overwrite another space's link.
func (s *Store) UpsertShare(ctx context.Context, shareID, spaceID uuid.UUID, ciphertext []byte) error {
	var owner uuid.UUID
	err := s.pool.QueryRow(ctx, "SELECT space_id FROM shares WHERE id = $1", shareID).Scan(&owner)
	switch {
	case err == nil && owner != spaceID:
		return ErrForbidden
	case err != nil && !errors.Is(err, pgx.ErrNoRows):
		return err
	}

	_, err = s.pool.Exec(ctx, "INSERT INTO shares (id, space_id, ciphertext, size_bytes) VALUES ($1, $2, $3, $4) ON CONFLICT (id) DO UPDATE SET ciphertext = EXCLUDED.ciphertext, size_bytes = EXCLUDED.size_bytes, updated_at = now()", shareID, spaceID, ciphertext, int64(len(ciphertext)))
	return err
}

// GetShare reads a share's ciphertext for an unauthenticated public reader.
// Args: ctx, shareID
// Returns: the sealed bytes, or ErrNotFound
// Handles: a revoked or never-created link, both of which are ErrNotFound so the
// two are indistinguishable from outside.
func (s *Store) GetShare(ctx context.Context, shareID uuid.UUID) ([]byte, error) {
	var ciphertext []byte
	if err := s.pool.QueryRow(ctx, "SELECT ciphertext FROM shares WHERE id = $1", shareID).Scan(&ciphertext); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return ciphertext, nil
}

// DeleteShare revokes a share link by destroying the ciphertext.
// Args: ctx, shareID, spaceID (scopes the delete so one space cannot revoke
// another's link)
// Returns: error, ErrNotFound when nothing matched
func (s *Store) DeleteShare(ctx context.Context, shareID, spaceID uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, "DELETE FROM shares WHERE id = $1 AND space_id = $2", shareID, spaceID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
