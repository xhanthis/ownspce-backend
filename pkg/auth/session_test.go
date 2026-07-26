package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

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
