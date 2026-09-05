package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Attachment is the server's whole record of one attached file: which space it
// belongs to, where its ciphertext sits in object storage, and how many bytes it
// occupies. The file name, type and dimensions live in the page's own
// ciphertext and never reach this table.
type Attachment struct {
	ID        uuid.UUID
	SpaceID   uuid.UUID
	BlobURL   string
	SizeBytes int64
	CreatedAt time.Time
	UpdatedAt time.Time
}

// CommitAttachment records an attachment whose bytes are already in object
// storage. It runs last on purpose: a row written before the upload landed would
// point at bytes that do not exist and render as permanently broken.
// Args: ctx, attachmentID (minted by the client and used as the storage key),
// spaceID, blobURL, sizeBytes
// Returns: the superseded blob URL when a retry replaced an earlier upload, so
// the caller can sweep it; empty string on first commit
// Handles: an id already owned by another space (ErrForbidden), and a retry of
// the same id within its space, which overwrites in place
func (s *Store) CommitAttachment(ctx context.Context, attachmentID, spaceID uuid.UUID, blobURL string, sizeBytes int64) (string, error) {
	var (
		owner    uuid.UUID
		previous string
	)
	err := s.pool.QueryRow(ctx, "SELECT space_id, blob_url FROM attachments WHERE id = $1", attachmentID).Scan(&owner, &previous)
	switch {
	case err == nil && owner != spaceID:
		return "", ErrForbidden
	case err != nil && !errors.Is(err, pgx.ErrNoRows):
		return "", err
	case errors.Is(err, pgx.ErrNoRows):
		previous = ""
	}

	if _, err := s.pool.Exec(ctx, "INSERT INTO attachments (id, space_id, blob_url, size_bytes) VALUES ($1, $2, $3, $4) ON CONFLICT (id) DO UPDATE SET blob_url = EXCLUDED.blob_url, size_bytes = EXCLUDED.size_bytes, updated_at = now()", attachmentID, spaceID, blobURL, sizeBytes); err != nil {
		return "", err
	}
	if previous == blobURL {
		return "", nil
	}
	return previous, nil
}

// GetAttachment reads one attachment's storage location, scoped to its space.
// Args: ctx, attachmentID, spaceID
// Returns: the attachment, or ErrNotFound when it does not exist in that space
func (s *Store) GetAttachment(ctx context.Context, attachmentID, spaceID uuid.UUID) (*Attachment, error) {
	var a Attachment
	if err := s.pool.QueryRow(ctx, "SELECT id, space_id, blob_url, size_bytes, created_at, updated_at FROM attachments WHERE id = $1 AND space_id = $2", attachmentID, spaceID).Scan(&a.ID, &a.SpaceID, &a.BlobURL, &a.SizeBytes, &a.CreatedAt, &a.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &a, nil
}

// DeleteAttachment removes an attachment row and reports the blob to sweep.
// Args: ctx, attachmentID, spaceID
// Returns: the stored blob URL so the caller can delete the object, or ErrNotFound
func (s *Store) DeleteAttachment(ctx context.Context, attachmentID, spaceID uuid.UUID) (string, error) {
	var blobURL string
	if err := s.pool.QueryRow(ctx, "DELETE FROM attachments WHERE id = $1 AND space_id = $2 RETURNING blob_url", attachmentID, spaceID).Scan(&blobURL); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", err
	}
	return blobURL, nil
}
