package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrTokenReuse   = errors.New("store: refresh token reuse")
	ErrTokenExpired = errors.New("store: refresh token expired")
)

const (
	// RefreshTTLWeb is the sliding window a browser session stays alive. Short,
	// because a logged-in browser profile is the easiest session to walk up to
	// and reuse, and re-authenticating there costs one click.
	RefreshTTLWeb = 7 * 24 * time.Hour
	// RefreshTTLApp is the window for an installed app. Its refresh token lives
	// in the Keychain / Keystore behind the device lock, so expiring the session
	// monthly buys almost nothing and costs the user a sign-in they never asked
	// for. Revocation stays instant either way: the auth middleware re-reads the
	// device row on every request.
	RefreshTTLApp = 365 * 24 * time.Hour
	// refreshReuseGrace forgives a token replayed within this window. When a
	// rotation response is lost in flight the server has already spent the token
	// the client still holds; without grace that single dropped packet revokes
	// the family and forces a re-login, which on a phone happens often.
	refreshReuseGrace = 60 * time.Second
)

// refreshTTLFor picks a session length from the device's platform.
// Args: platform (as registered by the client)
// Returns: the sliding window for that platform, defaulting to the app window
// for anything that is not the web client
func refreshTTLFor(platform string) time.Duration {
	if platform == DevicePlatformWeb {
		return RefreshTTLWeb
	}
	return RefreshTTLApp
}

// RefreshToken is the opaque credential handed to a device. Only its SHA-256 is
// stored, so a database leak yields no usable tokens.
type RefreshToken struct {
	Plaintext string
	FamilyID  uuid.UUID
	ExpiresAt time.Time
}

// IssueRefreshToken mints a new refresh token, starting a new family when
// familyID is nil.
// Args: ctx, userID, deviceID, platform (sets the session length), familyID (nil
// to start a family)
// Returns: token with plaintext (returned exactly once), error
func (s *Store) IssueRefreshToken(ctx context.Context, userID, deviceID uuid.UUID, platform string, familyID *uuid.UUID) (*RefreshToken, error) {
	plaintext, hash, err := newTokenSecret()
	if err != nil {
		return nil, err
	}
	family := uuid.New()
	if familyID != nil {
		family = *familyID
	}
	expires := time.Now().Add(refreshTTLFor(platform))

	if _, err := s.pool.Exec(ctx, "INSERT INTO refresh_tokens (user_id, device_id, token_hash, family_id, expires_at) VALUES ($1, $2, $3, $4, $5)", userID, deviceID, hash, family, expires); err != nil {
		return nil, err
	}
	return &RefreshToken{Plaintext: plaintext, FamilyID: family, ExpiresAt: expires}, nil
}

// RotatedToken is the outcome of a successful refresh: a fresh token plus the
// identity it authenticates.
type RotatedToken struct {
	UserID   uuid.UUID
	DeviceID uuid.UUID
	Token    *RefreshToken
}

// RotateRefreshToken exchanges a refresh token for its successor in the same
// family, detecting replay of an already-used token.
//
// A replay inside refreshReuseGrace is treated as an honest retry rather than
// theft: a client whose rotation response was lost holds a token the server has
// already spent, and it has no way to tell that from a network error. Only a
// replay after the grace window looks like a stolen token, and that still kills
// the family.
//
// Args: ctx, plaintext (token presented by the client)
// Returns: rotated token + identity, error
// Handles: unknown token (ErrNotFound), replay of a long-spent or revoked token
// (ErrTokenReuse — the whole family is revoked, forcing re-login), expiry
// (ErrTokenExpired), revoked device (ErrForbidden)
func (s *Store) RotateRefreshToken(ctx context.Context, plaintext string) (*RotatedToken, error) {
	hash := hashToken(plaintext)

	var (
		id        uuid.UUID
		userID    uuid.UUID
		deviceID  uuid.UUID
		familyID  uuid.UUID
		expiresAt time.Time
		status    string
		platform  string
	)
	row := s.pool.QueryRow(ctx, "SELECT t.id, t.user_id, t.device_id, t.family_id, t.expires_at, d.status, d.platform FROM refresh_tokens t JOIN devices d ON d.id = t.device_id WHERE t.token_hash = $1", hash)
	if err := row.Scan(&id, &userID, &deviceID, &familyID, &expiresAt, &status, &platform); err != nil {
		if noRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	if time.Now().After(expiresAt) {
		return nil, ErrTokenExpired
	}
	if status == DeviceStatusRevoked {
		return nil, ErrForbidden
	}

	nextPlaintext, nextHash, err := newTokenSecret()
	if err != nil {
		return nil, err
	}
	expires := time.Now().Add(refreshTTLFor(platform))

	reused := false
	err = s.tx(ctx, func(tx pgx.Tx) error {
		// One conditional claim decides everything: it stamps used_at on the first
		// rotation, still succeeds for a retry inside the grace window, and matches
		// nothing once the token is revoked or long spent. COALESCE keeps used_at
		// anchored to the first use so replaying cannot slide the window forward.
		tag, err := tx.Exec(ctx, "UPDATE refresh_tokens SET used_at = COALESCE(used_at, now()) WHERE id = $1 AND revoked_at IS NULL AND (used_at IS NULL OR used_at > now() - make_interval(secs => $2))", id, refreshReuseGrace.Seconds())
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			reused = true
			return nil
		}
		if _, err := tx.Exec(ctx, "INSERT INTO refresh_tokens (user_id, device_id, token_hash, family_id, expires_at) VALUES ($1, $2, $3, $4, $5)", userID, deviceID, nextHash, familyID, expires); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, "UPDATE devices SET last_seen_at = now() WHERE id = $1", deviceID)
		return err
	})
	if err != nil {
		return nil, err
	}
	// Revocation runs outside the transaction above: rolling it back with the
	// error would leave a detected-stolen token family alive.
	if reused {
		return nil, s.revokeFamily(ctx, familyID)
	}

	return &RotatedToken{UserID: userID, DeviceID: deviceID, Token: &RefreshToken{Plaintext: nextPlaintext, FamilyID: familyID, ExpiresAt: expires}}, nil
}

// revokeFamily kills every live token in a family and reports the reuse, so a
// stolen refresh token buys an attacker one request and costs the whole chain.
func (s *Store) revokeFamily(ctx context.Context, familyID uuid.UUID) error {
	if _, err := s.pool.Exec(ctx, "UPDATE refresh_tokens SET revoked_at = now() WHERE family_id = $1 AND revoked_at IS NULL", familyID); err != nil {
		return err
	}
	return ErrTokenReuse
}

// RevokeDeviceTokens revokes every live refresh token for a device (logout).
func (s *Store) RevokeDeviceTokens(ctx context.Context, deviceID uuid.UUID) error {
	_, err := s.pool.Exec(ctx, "UPDATE refresh_tokens SET revoked_at = now() WHERE device_id = $1 AND revoked_at IS NULL", deviceID)
	return err
}

func newTokenSecret() (plaintext string, hash []byte, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("generate refresh token: %w", err)
	}
	plaintext = base64.RawURLEncoding.EncodeToString(raw)
	return plaintext, hashToken(plaintext), nil
}

func hashToken(plaintext string) []byte {
	sum := sha256.Sum256([]byte(plaintext))
	return sum[:]
}

// RevokeTokenFamily revokes every live token in the family the presented token
// belongs to, without treating the presentation as a replay.
//
// Sign-out uses it on the cross-surface cookie. Rotation is the wrong tool
// there: it would hand back a successor nobody wants and, on a second sign-out,
// look exactly like the theft it is designed to punish.
// Args: ctx, plaintext (the token as presented)
// Returns: error; an unknown or already-revoked token is a no-op success,
// because signing out twice is not a failure
func (s *Store) RevokeTokenFamily(ctx context.Context, plaintext string) error {
	_, err := s.pool.Exec(ctx, "UPDATE refresh_tokens SET revoked_at = now() WHERE family_id = (SELECT family_id FROM refresh_tokens WHERE token_hash = $1) AND revoked_at IS NULL", hashToken(plaintext))
	return err
}
