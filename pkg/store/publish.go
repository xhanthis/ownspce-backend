package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Publish is a published page — the one place readable user content exists on the
// server, because the client decrypted it and asked for it to be public.
type Publish struct {
	ID            uuid.UUID
	UserID        uuid.UUID
	Username      string
	Slug          string
	HTMLBlobURL   string
	BlocksBlobURL string
	AssetBlobURLs []string
	OGTitle       string
	OGDescription string
	SizeBytes     int64
	Status        string
	PublishedAt   time.Time
	UpdatedAt     time.Time
}

// IsReservedName reports whether a username or slug is on the reserved list.
func (s *Store) IsReservedName(ctx context.Context, name string) (bool, error) {
	var reserved bool
	err := s.pool.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM reserved_names WHERE name = $1)", name).Scan(&reserved)
	return reserved, err
}

// CountPublishes returns how many live pages a user has, for quota checks.
func (s *Store) CountPublishes(ctx context.Context, userID uuid.UUID) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, "SELECT count(*) FROM publishes WHERE user_id = $1 AND status = 'live'", userID).Scan(&n)
	return n, err
}

// UpsertPublish creates or replaces a published page for (user, slug).
// Args: ctx, userID, slug, html/blocks blob URLs, asset URLs, OG metadata, sizeBytes
// Returns: publish row, previously stored blob URLs to clean up, error
// Handles: republish of an existing slug (blobs from the prior version returned
// for deletion), takedown status reset on republish
func (s *Store) UpsertPublish(ctx context.Context, userID uuid.UUID, slug, htmlURL, blocksURL string, assetURLs []string, ogTitle, ogDescription string, sizeBytes int64) (*Publish, []string, error) {
	if assetURLs == nil {
		assetURLs = []string{}
	}
	assets, err := json.Marshal(assetURLs)
	if err != nil {
		return nil, nil, err
	}
	// Sent as a string: under the PgBouncer-safe exec query mode a []byte is
	// encoded as bytea, which Postgres will not accept into a jsonb column.
	assetsJSON := string(assets)

	var (
		prevHTML   *string
		prevBlocks *string
		prevAssets []byte
	)
	_ = s.pool.QueryRow(ctx, "SELECT html_blob_url, blocks_blob_url, asset_blob_urls FROM publishes WHERE user_id = $1 AND slug = $2", userID, slug).Scan(&prevHTML, &prevBlocks, &prevAssets)

	var p Publish
	var assetsRaw []byte
	if err := s.pool.QueryRow(ctx, "INSERT INTO publishes (user_id, slug, html_blob_url, blocks_blob_url, asset_blob_urls, og_title, og_description, size_bytes) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (user_id, slug) DO UPDATE SET html_blob_url = EXCLUDED.html_blob_url, blocks_blob_url = EXCLUDED.blocks_blob_url, asset_blob_urls = EXCLUDED.asset_blob_urls, og_title = EXCLUDED.og_title, og_description = EXCLUDED.og_description, size_bytes = EXCLUDED.size_bytes, status = 'live', updated_at = now() RETURNING id, user_id, slug, html_blob_url, blocks_blob_url, asset_blob_urls, og_title, og_description, size_bytes, status, published_at, updated_at", userID, slug, htmlURL, blocksURL, assetsJSON, ogTitle, ogDescription, sizeBytes).Scan(&p.ID, &p.UserID, &p.Slug, &p.HTMLBlobURL, &p.BlocksBlobURL, &assetsRaw, &p.OGTitle, &p.OGDescription, &p.SizeBytes, &p.Status, &p.PublishedAt, &p.UpdatedAt); err != nil {
		return nil, nil, err
	}
	_ = json.Unmarshal(assetsRaw, &p.AssetBlobURLs)

	var stale []string
	if prevHTML != nil && *prevHTML != htmlURL {
		stale = append(stale, *prevHTML)
	}
	if prevBlocks != nil && *prevBlocks != blocksURL {
		stale = append(stale, *prevBlocks)
	}
	if len(prevAssets) > 0 {
		var old []string
		if json.Unmarshal(prevAssets, &old) == nil {
			keep := map[string]bool{}
			for _, u := range assetURLs {
				keep[u] = true
			}
			for _, u := range old {
				if !keep[u] {
					stale = append(stale, u)
				}
			}
		}
	}
	return &p, stale, nil
}

func (s *Store) ListPublishes(ctx context.Context, userID uuid.UUID) ([]Publish, error) {
	rows, err := s.pool.Query(ctx, "SELECT id, user_id, slug, html_blob_url, blocks_blob_url, og_title, og_description, size_bytes, status, published_at, updated_at FROM publishes WHERE user_id = $1 ORDER BY published_at DESC", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Publish
	for rows.Next() {
		var p Publish
		if err := rows.Scan(&p.ID, &p.UserID, &p.Slug, &p.HTMLBlobURL, &p.BlocksBlobURL, &p.OGTitle, &p.OGDescription, &p.SizeBytes, &p.Status, &p.PublishedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// DeletePublish unpublishes a page.
// Args: ctx, userID, slug
// Returns: blob URLs that should now be deleted, error (ErrNotFound if absent)
func (s *Store) DeletePublish(ctx context.Context, userID uuid.UUID, slug string) ([]string, error) {
	var (
		htmlURL   string
		blocksURL string
		assetsRaw []byte
	)
	if err := s.pool.QueryRow(ctx, "DELETE FROM publishes WHERE user_id = $1 AND slug = $2 RETURNING html_blob_url, blocks_blob_url, asset_blob_urls", userID, slug).Scan(&htmlURL, &blocksURL, &assetsRaw); err != nil {
		if noRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	urls := []string{htmlURL, blocksURL}
	var assets []string
	if json.Unmarshal(assetsRaw, &assets) == nil {
		urls = append(urls, assets...)
	}
	return urls, nil
}

// GetPublicPage resolves @username/slug for the public serving route.
// Args: ctx, username, slug
// Returns: publish row with username filled, error (ErrNotFound unknown page,
// ErrForbidden when taken down)
func (s *Store) GetPublicPage(ctx context.Context, username, slug string) (*Publish, error) {
	var p Publish
	var assetsRaw []byte
	if err := s.pool.QueryRow(ctx, "SELECT p.id, p.user_id, u.username, p.slug, p.html_blob_url, p.blocks_blob_url, p.asset_blob_urls, p.og_title, p.og_description, p.size_bytes, p.status, p.published_at, p.updated_at FROM publishes p JOIN users u ON u.id = p.user_id WHERE u.username = $1 AND p.slug = $2", username, slug).Scan(&p.ID, &p.UserID, &p.Username, &p.Slug, &p.HTMLBlobURL, &p.BlocksBlobURL, &assetsRaw, &p.OGTitle, &p.OGDescription, &p.SizeBytes, &p.Status, &p.PublishedAt, &p.UpdatedAt); err != nil {
		if noRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	_ = json.Unmarshal(assetsRaw, &p.AssetBlobURLs)
	if p.Status != "live" {
		return &p, ErrForbidden
	}
	return &p, nil
}

// InsertAbuseReport records a public report against a published page.
func (s *Store) InsertAbuseReport(ctx context.Context, publishID uuid.UUID, reporterIPHash []byte, reason, details string) error {
	_, err := s.pool.Exec(ctx, "INSERT INTO abuse_reports (publish_id, reporter_ip_hash, reason, details) VALUES ($1, $2, $3, $4)", publishID, reporterIPHash, reason, details)
	return err
}
