package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// User holds Tier 0 data only — every field here is deliberately readable by the
// server. Nothing derived from note content may ever be added to this struct.
type User struct {
	ID                uuid.UUID
	Email             string
	Name              string
	Username          *string
	AvatarURL         *string
	Plan              string
	RecoveryPublicKey []byte
	StreakCount       int
	StreakUpdatedOn   *time.Time
	Theme             string
	Language          string
	NotifyEmail       bool
	NotifyPush        bool
	CreatedAt         time.Time
}

const userColumns = `id, email, name, username, avatar_url, plan, recovery_public_key, streak_count, streak_updated_on, theme, language, notify_email, notify_push, created_at`

func scanUser(row pgx.Row) (*User, error) {
	var u User
	if err := row.Scan(&u.ID, &u.Email, &u.Name, &u.Username, &u.AvatarURL, &u.Plan, &u.RecoveryPublicKey, &u.StreakCount, &u.StreakUpdatedOn, &u.Theme, &u.Language, &u.NotifyEmail, &u.NotifyPush, &u.CreatedAt); err != nil {
		if noRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &u, nil
}

// UpsertUserByProvider resolves a verified Google/Apple identity to a user row,
// creating it on first sign-in and linking by verified email when the same
// person arrives via a second provider.
// Args: ctx, provider ("google"|"apple"), sub (provider subject), email, name, avatarURL
// Returns: user, created (true on first-ever sign-in), error
// Handles: provider-subject match, email link, concurrent first sign-in races
func (s *Store) UpsertUserByProvider(ctx context.Context, provider, sub, email, name, avatarURL string) (*User, bool, error) {
	subColumn := "google_sub"
	if provider == "apple" {
		subColumn = "apple_sub"
	}

	u, err := scanUser(s.pool.QueryRow(ctx, "SELECT "+userColumns+" FROM users WHERE "+subColumn+" = $1", sub))
	if err == nil {
		return u, false, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, false, err
	}

	u, err = scanUser(s.pool.QueryRow(ctx, "UPDATE users SET "+subColumn+" = $1, name = CASE WHEN name = '' THEN $2 ELSE name END, avatar_url = COALESCE(avatar_url, $3), updated_at = now() WHERE email = $4 AND "+subColumn+" IS NULL RETURNING "+userColumns, sub, name, nullIfEmpty(avatarURL), email))
	if err == nil {
		return u, false, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, false, err
	}

	u, err = scanUser(s.pool.QueryRow(ctx, "INSERT INTO users (email, "+subColumn+", name, avatar_url) VALUES ($1, $2, $3, $4) RETURNING "+userColumns, email, sub, name, nullIfEmpty(avatarURL)))
	if err == nil {
		return u, true, nil
	}
	if isUniqueViolation(err, "") {
		u, lookupErr := scanUser(s.pool.QueryRow(ctx, "SELECT "+userColumns+" FROM users WHERE email = $1", email))
		if lookupErr != nil {
			return nil, false, lookupErr
		}
		return u, false, nil
	}
	return nil, false, err
}

func (s *Store) GetUser(ctx context.Context, id uuid.UUID) (*User, error) {
	return scanUser(s.pool.QueryRow(ctx, "SELECT "+userColumns+" FROM users WHERE id = $1", id))
}

func (s *Store) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	return scanUser(s.pool.QueryRow(ctx, "SELECT "+userColumns+" FROM users WHERE username = $1", username))
}

// ProfilePatch carries the mutable Tier 0 profile fields; nil means "unchanged".
type ProfilePatch struct {
	Name              *string
	Username          *string
	AvatarURL         *string
	Theme             *string
	Language          *string
	NotifyEmail       *bool
	NotifyPush        *bool
	StreakCount       *int
	StreakUpdatedOn   *time.Time
	RecoveryPublicKey []byte
}

// UpdateProfile applies a partial Tier 0 profile update.
// Args: ctx, id, patch (nil fields untouched)
// Returns: refreshed user, or error
// Handles: taken username (ErrConflict), reserved username (ErrForbidden), empty patch
func (s *Store) UpdateProfile(ctx context.Context, id uuid.UUID, patch ProfilePatch) (*User, error) {
	if patch.Username != nil {
		var reserved bool
		if err := s.pool.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM reserved_names WHERE name = $1)", *patch.Username).Scan(&reserved); err != nil {
			return nil, err
		}
		if reserved {
			return nil, ErrForbidden
		}
	}

	u, err := scanUser(s.pool.QueryRow(ctx, "UPDATE users SET name = COALESCE($2, name), username = COALESCE($3, username), avatar_url = COALESCE($4, avatar_url), theme = COALESCE($5, theme), language = COALESCE($6, language), notify_email = COALESCE($7, notify_email), notify_push = COALESCE($8, notify_push), streak_count = COALESCE($9, streak_count), streak_updated_on = COALESCE($10, streak_updated_on), recovery_public_key = COALESCE($11, recovery_public_key), updated_at = now() WHERE id = $1 RETURNING "+userColumns, id, patch.Name, patch.Username, patch.AvatarURL, patch.Theme, patch.Language, patch.NotifyEmail, patch.NotifyPush, patch.StreakCount, patch.StreakUpdatedOn, nullIfEmptyBytes(patch.RecoveryPublicKey)))
	if err != nil && isUniqueViolation(err, "users_username_key") {
		return nil, ErrConflict
	}
	return u, err
}

func nullIfEmpty(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}

func nullIfEmptyBytes(v []byte) []byte {
	if len(v) == 0 {
		return nil
	}
	return v
}
