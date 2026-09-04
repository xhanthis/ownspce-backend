package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	// EmailCodePurposeSignIn mints a session from an email address alone.
	EmailCodePurposeSignIn = "signin"
	// EmailCodePurposeDevice activates one already-signed-in device.
	EmailCodePurposeDevice = "device"

	emailCodeTTL = 10 * time.Minute
	// A code is six digits, so guessing is only hard because the attempt count
	// is small. Five is enough for a typo and far short of a million.
	emailCodeMaxAttempts = 5
	// Codes an address may be sent in an hour, which is also the cap on how
	// often somebody else's inbox can be used as a weapon.
	emailCodeMaxPerHour = 5
)

var (
	// ErrCodeInvalid covers every "that is not the code" case — wrong, expired,
	// already used, or never issued. They are one error on purpose: telling a
	// caller which one it was tells an attacker which addresses have codes.
	ErrCodeInvalid = errors.New("store: email code invalid")
	// ErrCodeThrottled means stop and ask for a fresh code.
	ErrCodeThrottled = errors.New("store: email code throttled")
)

// NormalizeEmail lowercases and trims an address so the same person typing
// " Rahul@Example.com " twice hits the same rate-limit bucket and the same row.
// The column is citext, so this is about the bucket key, not the lookup.
func NormalizeEmail(raw string) string { return strings.ToLower(strings.TrimSpace(raw)) }

// EmailCodeTTL is how long a minted code stays usable, exported so the HTTP
// layer can tell the person rather than making them find out.
func EmailCodeTTL() time.Duration { return emailCodeTTL }

// IssueEmailCode mints a six-digit code for an address and files only its hash.
//
// Any live code for the same address and purpose is consumed first, so the most
// recent mail is always the one that works — two codes in flight is how somebody
// ends up typing the older one and being told they are wrong.
// Args: ctx, email, purpose (signin|device), userID and deviceID (nil for a
// sign-in to an address with no account yet)
// Returns: the plaintext code to mail, its expiry, error
// Handles: an address being flooded with codes (ErrCodeThrottled past five an
// hour), and old rows, swept opportunistically here rather than by a cron
func (s *Store) IssueEmailCode(ctx context.Context, email, purpose string, userID, deviceID *uuid.UUID) (string, time.Time, error) {
	email = NormalizeEmail(email)
	code, err := mintNumericCode()
	if err != nil {
		return "", time.Time{}, err
	}
	sum := sha256.Sum256([]byte(code))
	expiresAt := time.Now().UTC().Add(emailCodeTTL)

	err = s.tx(ctx, func(tx pgx.Tx) error {
		var recent int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM email_codes WHERE email = $1 AND purpose = $2 AND created_at > now() - interval '1 hour'", email, purpose).Scan(&recent); err != nil {
			return err
		}
		if recent >= emailCodeMaxPerHour {
			return ErrCodeThrottled
		}
		if _, err := tx.Exec(ctx, "UPDATE email_codes SET consumed_at = now() WHERE email = $1 AND purpose = $2 AND consumed_at IS NULL", email, purpose); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "DELETE FROM email_codes WHERE expires_at < now() - interval '1 day'"); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, "INSERT INTO email_codes (email, purpose, user_id, device_id, code_hash, expires_at) VALUES ($1, $2, $3, $4, $5, $6)", email, purpose, userID, deviceID, sum[:], expiresAt)
		return err
	})
	if err != nil {
		return "", time.Time{}, err
	}
	return code, expiresAt, nil
}

// ConsumeEmailCode verifies a code and burns it in the same transaction.
//
// The row is locked before the comparison so two racing submissions of one code
// cannot both succeed — which for the device purpose would activate a device
// twice and for sign-in would mint two sessions from one mail.
// Args: ctx, email, purpose, code (as typed), deviceID (required for the device
// purpose, and checked against the code's own binding)
// Returns: the user the code was issued for (nil when the address had no account
// yet), error
// Handles: no code, expired code, spent code, wrong code (all ErrCodeInvalid,
// with the attempt counted), and a code bound to a different device
func (s *Store) ConsumeEmailCode(ctx context.Context, email, purpose, code string, deviceID *uuid.UUID) (*uuid.UUID, error) {
	email = NormalizeEmail(email)
	code = strings.TrimSpace(code)
	sum := sha256.Sum256([]byte(code))

	// A rejection has to be committed, not rolled back: the attempt counter is
	// the only thing making a six-digit code safe, and returning the failure
	// from inside the transaction would undo every increment along with it. So
	// the verdict travels out in a variable and only real database faults are
	// returned from the callback.
	var (
		userID  *uuid.UUID
		outcome error
	)
	err := s.tx(ctx, func(tx pgx.Tx) error {
		var (
			id        uuid.UUID
			hash      []byte
			attempts  int
			expiresAt time.Time
			owner     *uuid.UUID
			boundTo   *uuid.UUID
		)
		row := tx.QueryRow(ctx, "SELECT id, code_hash, attempts, expires_at, user_id, device_id FROM email_codes WHERE email = $1 AND purpose = $2 AND consumed_at IS NULL ORDER BY created_at DESC LIMIT 1 FOR UPDATE", email, purpose)
		if err := row.Scan(&id, &hash, &attempts, &expiresAt, &owner, &boundTo); err != nil {
			if noRows(err) {
				outcome = ErrCodeInvalid
				return nil
			}
			return err
		}

		if time.Now().UTC().After(expiresAt) {
			outcome = ErrCodeInvalid
			_, err := tx.Exec(ctx, "UPDATE email_codes SET consumed_at = now() WHERE id = $1", id)
			return err
		}
		if attempts >= emailCodeMaxAttempts {
			outcome = ErrCodeThrottled
			return nil
		}

		deviceMatches := boundTo == nil || (deviceID != nil && *boundTo == *deviceID)
		if subtle.ConstantTimeCompare(hash, sum[:]) != 1 || !deviceMatches {
			outcome = ErrCodeInvalid
			_, err := tx.Exec(ctx, "UPDATE email_codes SET attempts = attempts + 1 WHERE id = $1", id)
			return err
		}

		if _, err := tx.Exec(ctx, "UPDATE email_codes SET consumed_at = now() WHERE id = $1", id); err != nil {
			return err
		}
		userID = owner
		return nil
	})
	if err != nil {
		return nil, err
	}
	return userID, outcome
}

// mintNumericCode returns a uniformly random six-digit code, leading zeros kept.
// Digits rather than base32 because the code is read off a phone and typed into
// another device, where an l/1 confusion costs an attempt.
func mintNumericCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}
