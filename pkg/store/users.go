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
// EscrowPublicKey is stored in the column recovery_public_key. The name is
// historical: the key it holds used to be derived from a phrase the person kept,
// and is now an escrow key the server holds for them. Renaming the column would
// break every deployed client and every running API instance the moment the
// migration landed, which is exactly how this went wrong once already.
type User struct {
	ID              uuid.UUID
	Email           string
	Name            string
	Username        *string
	AvatarURL       *string
	Plan            string
	EscrowPublicKey []byte
	StreakCount     int
	StreakUpdatedOn *time.Time
	Theme           string
	Font            string
	Palette         string
	Language        string
	NotifyEmail     bool
	NotifyPush      bool
	CreatedAt       time.Time
}

const userColumns = `id, email, name, username, avatar_url, plan, recovery_public_key, streak_count, streak_updated_on, theme, font, palette, language, notify_email, notify_push, created_at`

func scanUser(row pgx.Row) (*User, error) {
	var u User
	if err := row.Scan(&u.ID, &u.Email, &u.Name, &u.Username, &u.AvatarURL, &u.Plan, &u.EscrowPublicKey, &u.StreakCount, &u.StreakUpdatedOn, &u.Theme, &u.Font, &u.Palette, &u.Language, &u.NotifyEmail, &u.NotifyPush, &u.CreatedAt); err != nil {
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

// UpsertUserByEmail resolves a verified email address to a user row, creating it
// on first sign-in.
//
// The address is the account. Somebody who signed up with Google and later types
// the same address lands on the same row and keeps every household on it, which
// is the whole reason there is one account across notes and money rather than
// one per provider.
// Args: ctx, email (already proven by a consumed code — this function does not
// prove anything itself)
// Returns: user, created (true on first-ever sign-in), error
// Handles: a concurrent first sign-in of the same address, which loses the
// insert race and reads the winner's row rather than failing
func (s *Store) UpsertUserByEmail(ctx context.Context, email string) (*User, bool, error) {
	email = NormalizeEmail(email)

	u, err := scanUser(s.pool.QueryRow(ctx, "SELECT "+userColumns+" FROM users WHERE email = $1", email))
	if err == nil {
		return u, false, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, false, err
	}

	u, err = scanUser(s.pool.QueryRow(ctx, "INSERT INTO users (email) VALUES ($1) RETURNING "+userColumns, email))
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

// EscrowKey reads the account's escrow keypair: the public half clients wrap
// household keys to, and the private half sealed under the master key.
// Args: ctx, userID
// Returns: public key, sealed private key (both nil when the account has none
// yet), error
func (s *Store) EscrowKey(ctx context.Context, userID uuid.UUID) (publicKey, sealedPrivateKey []byte, err error) {
	err = s.pool.QueryRow(ctx, "SELECT recovery_public_key, escrow_private_key FROM users WHERE id = $1", userID).Scan(&publicKey, &sealedPrivateKey)
	if err != nil {
		if noRows(err) {
			return nil, nil, ErrNotFound
		}
		return nil, nil, err
	}
	return publicKey, sealedPrivateKey, nil
}

// SetEscrowKey installs a freshly minted escrow keypair, once.
//
// The WHERE clause is the whole safety property. An account gets an escrow key
// exactly once and never has it replaced, because replacing it would strand
// every household key already sealed to the old one — the server would hold
// wraps it could no longer open, and a recovery would hand a device a ledger of
// noise. A concurrent second minting loses the WHERE and is discarded.
//
// Accounts that predate escrow may carry a public key derived from the old
// 24-word phrase and no private key. Those do get an escrow key here, and any
// space key still sealed to the retired phrase key becomes unopenable — which
// EscrowRecovery reports honestly rather than papering over.
// Args: ctx, userID, publicKey, sealedPrivateKey
// Returns: whether this call was the one that installed the key, error
func (s *Store) SetEscrowKey(ctx context.Context, userID uuid.UUID, publicKey, sealedPrivateKey []byte) (bool, error) {
	tag, err := s.pool.Exec(ctx, "UPDATE users SET recovery_public_key = $2, escrow_private_key = $3, updated_at = now() WHERE id = $1 AND escrow_private_key IS NULL", userID, publicKey, sealedPrivateKey)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// UserByEmail looks an account up by address without creating one.
func (s *Store) UserByEmail(ctx context.Context, email string) (*User, error) {
	return scanUser(s.pool.QueryRow(ctx, "SELECT "+userColumns+" FROM users WHERE email = $1", NormalizeEmail(email)))
}

func (s *Store) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	return scanUser(s.pool.QueryRow(ctx, "SELECT "+userColumns+" FROM users WHERE username = $1", username))
}

// ProfilePatch carries the mutable Tier 0 profile fields; nil means "unchanged".
type ProfilePatch struct {
	Name            *string
	Username        *string
	AvatarURL       *string
	Theme           *string
	Font            *string
	Palette         *string
	Language        *string
	NotifyEmail     *bool
	NotifyPush      *bool
	StreakCount     *int
	StreakUpdatedOn *time.Time
	EscrowPublicKey []byte
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

	u, err := scanUser(s.pool.QueryRow(ctx, "UPDATE users SET name = COALESCE($2, name), username = COALESCE($3, username), avatar_url = COALESCE($4, avatar_url), theme = COALESCE($5, theme), font = COALESCE($6, font), palette = COALESCE($7, palette), language = COALESCE($8, language), notify_email = COALESCE($9, notify_email), notify_push = COALESCE($10, notify_push), streak_count = COALESCE($11, streak_count), streak_updated_on = COALESCE($12, streak_updated_on), recovery_public_key = COALESCE($13, recovery_public_key), updated_at = now() WHERE id = $1 RETURNING "+userColumns, id, patch.Name, patch.Username, patch.AvatarURL, patch.Theme, patch.Font, patch.Palette, patch.Language, patch.NotifyEmail, patch.NotifyPush, patch.StreakCount, patch.StreakUpdatedOn, nullIfEmptyBytes(patch.EscrowPublicKey)))
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
