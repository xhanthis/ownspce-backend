package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// fakeProvider stands in for Google's JWKS endpoint so ID-token verification can be
// tested without network access or a real Google account.
type fakeProvider struct {
	key    *rsa.PrivateKey
	kid    string
	server *httptest.Server
}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}

	p := &fakeProvider{key: key, kid: "test-kid-1"}
	p.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := map[string]any{"keys": []map[string]string{{
			"kty": "RSA",
			"kid": p.kid,
			"n":   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString([]byte{0x01, 0x00, 0x01}),
		}}}
		_ = json.NewEncoder(w).Encode(doc)
	}))
	t.Cleanup(p.server.Close)
	return p
}

func (p *fakeProvider) idToken(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = p.kid
	signed, err := token.SignedString(p.key)
	if err != nil {
		t.Fatalf("sign id token: %v", err)
	}
	return signed
}

func testVerifier(p *fakeProvider, audiences ...string) *Verifier {
	v := NewVerifier(audiences, nil)
	v.googleJWKS = p.server.URL
	return v
}

func baseClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"iss":            googleIssuerA,
		"aud":            "client-web",
		"sub":            "google-subject-123",
		"email":          "Person@Example.com",
		"email_verified": true,
		"name":           "Test Person",
		"picture":        "https://example.com/a.png",
		"iat":            time.Now().Add(-time.Minute).Unix(),
		"exp":            time.Now().Add(time.Hour).Unix(),
	}
}

func TestVerifyAcceptsValidGoogleToken(t *testing.T) {
	// Arrange
	p := newFakeProvider(t)
	v := testVerifier(p, "client-web")
	token := p.idToken(t, baseClaims())

	// Act
	identity, err := v.Verify(context.Background(), ProviderGoogle, token)

	// Assert
	if err != nil {
		t.Fatalf("expected valid token, got error: %v", err)
	}
	if identity.Subject != "google-subject-123" {
		t.Errorf("subject = %q, want google-subject-123", identity.Subject)
	}
	if identity.Email != "person@example.com" {
		t.Errorf("email = %q, want lowercased person@example.com", identity.Email)
	}
}

func TestVerifyRejectsWrongAudience(t *testing.T) {
	p := newFakeProvider(t)
	v := testVerifier(p, "client-ios")
	token := p.idToken(t, baseClaims())

	_, err := v.Verify(context.Background(), ProviderGoogle, token)

	if !errors.Is(err, ErrAudienceMismatch) {
		t.Fatalf("expected ErrAudienceMismatch, got %v", err)
	}
}

func TestVerifyRejectsUnverifiedEmail(t *testing.T) {
	p := newFakeProvider(t)
	v := testVerifier(p, "client-web")
	claims := baseClaims()
	claims["email_verified"] = false
	token := p.idToken(t, claims)

	_, err := v.Verify(context.Background(), ProviderGoogle, token)

	if !errors.Is(err, ErrEmailUnverified) {
		t.Fatalf("expected ErrEmailUnverified, got %v", err)
	}
}

func TestVerifyAcceptsAppleStringEmailVerified(t *testing.T) {
	p := newFakeProvider(t)
	v := NewVerifier(nil, []string{"com.ownspce.app"})
	v.appleJWKS = p.server.URL
	claims := baseClaims()
	claims["iss"] = appleIssuer
	claims["aud"] = "com.ownspce.app"
	claims["email_verified"] = "true"
	token := p.idToken(t, claims)

	identity, err := v.Verify(context.Background(), ProviderApple, token)

	if err != nil {
		t.Fatalf("expected valid apple token, got %v", err)
	}
	if identity.Provider != ProviderApple {
		t.Errorf("provider = %q, want apple", identity.Provider)
	}
}

func TestVerifyRejectsExpiredToken(t *testing.T) {
	p := newFakeProvider(t)
	v := testVerifier(p, "client-web")
	claims := baseClaims()
	claims["exp"] = time.Now().Add(-time.Hour).Unix()
	token := p.idToken(t, claims)

	_, err := v.Verify(context.Background(), ProviderGoogle, token)

	if !errors.Is(err, ErrInvalidIDToken) {
		t.Fatalf("expected ErrInvalidIDToken for expired token, got %v", err)
	}
}

func TestVerifyRejectsTokenSignedByAnotherKey(t *testing.T) {
	p := newFakeProvider(t)
	attacker := newFakeProvider(t)
	attacker.kid = p.kid
	v := testVerifier(p, "client-web")
	token := attacker.idToken(t, baseClaims())

	_, err := v.Verify(context.Background(), ProviderGoogle, token)

	if err == nil {
		t.Fatal("expected verification to fail for a foreign signing key")
	}
}

func TestVerifyRejectsUnconfiguredProvider(t *testing.T) {
	p := newFakeProvider(t)
	v := NewVerifier(nil, nil)
	v.googleJWKS = p.server.URL

	_, err := v.Verify(context.Background(), ProviderGoogle, p.idToken(t, baseClaims()))

	if !errors.Is(err, ErrNoAudienceConfigured) {
		t.Fatalf("expected ErrNoAudienceConfigured, got %v", err)
	}
}
