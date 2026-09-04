package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func newTestSigner(t *testing.T) *Signer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return NewSigner(priv, pub)
}

func TestMintAndVerifyRoundTrip(t *testing.T) {
	// Arrange
	signer := newTestSigner(t)
	userID, deviceID := uuid.New(), uuid.New()

	// Act
	token, expires, err := signer.Mint(userID, deviceID)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	verified, err := signer.Verify(token)

	// Assert
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if verified.UserID != userID {
		t.Errorf("user = %s, want %s", verified.UserID, userID)
	}
	if verified.DeviceID != deviceID {
		t.Errorf("device = %s, want %s", verified.DeviceID, deviceID)
	}
	if expires.IsZero() {
		t.Error("expiry should be set")
	}
}

func TestVerifyRejectsTokenFromAnotherSigner(t *testing.T) {
	mine := newTestSigner(t)
	theirs := newTestSigner(t)
	token, _, err := theirs.Mint(uuid.New(), uuid.New())
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	_, err = mine.Verify(token)

	if !errors.Is(err, ErrInvalidAccessToken) {
		t.Fatalf("expected ErrInvalidAccessToken, got %v", err)
	}
}

func TestVerifyRejectsTamperedToken(t *testing.T) {
	signer := newTestSigner(t)
	token, _, err := signer.Mint(uuid.New(), uuid.New())
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	parts := strings.Split(token, ".")
	tampered := parts[0] + "." + parts[1] + "x." + parts[2]

	if _, err := signer.Verify(tampered); err == nil {
		t.Fatal("expected tampered token to be rejected")
	}
}

func TestJWKSExposesOnlyPublicKey(t *testing.T) {
	signer := newTestSigner(t)

	doc := signer.JWKS()

	keys, ok := doc["keys"].([]map[string]any)
	if !ok || len(keys) != 1 {
		t.Fatalf("expected exactly one key, got %#v", doc["keys"])
	}
	if keys[0]["crv"] != "Ed25519" || keys[0]["x"] == "" {
		t.Errorf("unexpected jwk: %#v", keys[0])
	}
	if _, leaked := keys[0]["d"]; leaked {
		t.Error("jwks must never contain the private scalar")
	}
}

// TestContinuationAndAccessTokensAreNotInterchangeable is the separation the
// continuation cookie depends on. One key signs both, so only the audience keeps
// them apart — and they are not equivalent powers: an access token lives in
// client memory, while a continuation cookie the browser sends automatically can
// register a device and collect escrow keys.
func TestContinuationAndAccessTokensAreNotInterchangeable(t *testing.T) {
	// Arrange
	signer := newTestSigner(t)
	userID, deviceID := uuid.New(), uuid.New()

	access, _, err := signer.Mint(userID, deviceID)
	if err != nil {
		t.Fatalf("mint access: %v", err)
	}
	continuation, _, err := signer.MintContinuation(userID, deviceID)
	if err != nil {
		t.Fatalf("mint continuation: %v", err)
	}

	// Act & Assert — each opens its own door and neither opens the other's.
	if _, err := signer.VerifyContinuation(access); err == nil {
		t.Error("an access token was accepted as a continuation token")
	}
	if _, err := signer.Verify(continuation); err == nil {
		t.Error("a continuation token was accepted as an access token")
	}

	verified, err := signer.VerifyContinuation(continuation)
	if err != nil {
		t.Fatalf("verify continuation: %v", err)
	}
	if verified.UserID != userID || verified.DeviceID != deviceID {
		t.Fatalf("continuation carried %s/%s, want %s/%s", verified.UserID, verified.DeviceID, userID, deviceID)
	}
}

// TestExpiredContinuationIsRefused pins the fortnight. The cookie outlives every
// tab it was minted in, so the expiry is the only thing bounding how long a
// stale browser can still let a new device into an account.
func TestExpiredContinuationIsRefused(t *testing.T) {
	// Arrange — the same claims MintContinuation builds, dated into the past.
	signer := newTestSigner(t)
	userID, deviceID := uuid.New(), uuid.New()
	issued := time.Now().Add(-2 * ContinuationTTL)

	claims := SessionClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    Issuer,
			Subject:   userID.String(),
			Audience:  jwt.ClaimStrings{continuationAudience},
			IssuedAt:  jwt.NewNumericDate(issued),
			NotBefore: jwt.NewNumericDate(issued),
			ExpiresAt: jwt.NewNumericDate(issued.Add(ContinuationTTL)),
			ID:        uuid.NewString(),
		},
		DeviceID: deviceID.String(),
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(signer.private)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Act
	_, err = signer.VerifyContinuation(token)

	// Assert
	if err == nil {
		t.Fatal("a continuation token that expired a fortnight ago was accepted")
	}
	if !errors.Is(err, ErrInvalidAccessToken) {
		t.Fatalf("err = %v, want ErrInvalidAccessToken", err)
	}
}
