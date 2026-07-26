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

// RefreshTTL is the sliding window a refresh-token family stays alive.
const RefreshTTL = 30 * 24 * time.Hour

// RefreshToken is the opaque credential handed to a device. Only its SHA-256 is
// stored, so a database leak yields no usable tokens.
type RefreshToken struct {
	Plaintext string
	FamilyID  uuid.UUID
	ExpiresAt time.Time
}

// IssueRefreshToken mints a new refresh token, starting a new family when
// familyID is nil.
// Args: ctx, userID, deviceID, familyID (nil to start a family)
// Returns: token with plaintext (returned exactly once), error
func (s *Store) IssueRefreshToken(ctx context.Context, userID, deviceID uuid.UUID, familyID *uuid.UUID) (*RefreshToken, error) {
	plaintext, hash, err := newTokenSecret()
	if err != nil {
		return nil, err
	}
	family := uuid.New()
	if familyID != nil {
		family = *familyID
	}
	expires := time.Now().Add(RefreshTTL)

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
// Args: ctx, plaintext (token presented by the client)
// Returns: rotated token + identity, error
// Handles: unknown token (ErrNotFound), replay of a spent or revoked token
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
		usedAt    *time.Time
		revokedAt *time.Time
		status    string
	)
	row := s.pool.QueryRow(ctx, "SELECT t.id, t.user_id, t.device_id, t.family_id, t.expires_at, t.used_at, t.revoked_at, d.status FROM refresh_tokens t JOIN devices d ON d.id = t.device_id WHERE t.token_hash = $1", hash)
	if err := row.Scan(&id, &userID, &deviceID, &familyID, &expiresAt, &usedAt, &revokedAt, &status); err != nil {
		if noRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	// Revocation runs outside any transaction that then fails: rolling it back with
	// the error would leave a detected-stolen token family alive.
	if usedAt != nil || revokedAt != nil {
		return nil, s.revokeFamily(ctx, familyID)
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
	expires := time.Now().Add(RefreshTTL)

	raced := false
	err = s.tx(ctx, func(tx pgx.Tx) error {
		// Claiming the token conditionally is what makes concurrent rotation safe:
		// exactly one caller can flip used_at, and the loser is treated as a replay.
		tag, err := tx.Exec(ctx, "UPDATE refresh_tokens SET used_at = now() WHERE id = $1 AND used_at IS NULL AND revoked_at IS NULL", id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			raced = true
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
	if raced {
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
