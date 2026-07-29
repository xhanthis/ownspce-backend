package auth

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	Issuer   = "https://api.ownspce.com"
	Audience = "ownspce"
	// AccessTokenTTL is deliberately not the revocation window: the middleware
	// re-reads the device row on every request, so a revoked device dies at once.
	// Its real job is to bound how often a client rotates its refresh token, and
	// every rotation is a chance for a dropped response to cost the user a login.
	AccessTokenTTL = time.Hour
)

var ErrInvalidAccessToken = errors.New("auth: invalid access token")

// SessionClaims is the access-token payload. It names the user AND the device,
// because revocation is per-device: the middleware re-checks the device row on
// every request, so a revoked device loses access immediately rather than when
// the token expires.
type SessionClaims struct {
	jwt.RegisteredClaims
	DeviceID string `json:"dev"`
}

// Signer mints and verifies access tokens with an Ed25519 keypair.
type Signer struct {
	private ed25519.PrivateKey
	public  ed25519.PublicKey
}

func NewSigner(private ed25519.PrivateKey, public ed25519.PublicKey) *Signer {
	return &Signer{private: private, public: public}
}

// Mint issues a short-lived access token for a user/device pair.
// Args: userID, deviceID
// Returns: signed token, expiry, error
func (s *Signer) Mint(userID, deviceID uuid.UUID) (string, time.Time, error) {
	now := time.Now()
	expires := now.Add(AccessTokenTTL)
	claims := SessionClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    Issuer,
			Subject:   userID.String(),
			Audience:  jwt.ClaimStrings{Audience},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expires),
			ID:        uuid.NewString(),
		},
		DeviceID: deviceID.String(),
	}

	token, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(s.private)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign access token: %w", err)
	}
	return token, expires, nil
}

// Verified is the identity carried by a valid access token.
type Verified struct {
	UserID   uuid.UUID
	DeviceID uuid.UUID
	TokenID  string
}

// Verify validates an access token's signature and registered claims.
// Args: raw token string
// Returns: verified identity, error
// Handles: wrong algorithm, expired or not-yet-valid tokens, wrong issuer or
// audience, malformed subject/device ids
func (s *Signer) Verify(raw string) (*Verified, error) {
	var claims SessionClaims
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"EdDSA"}), jwt.WithExpirationRequired(), jwt.WithIssuer(Issuer), jwt.WithAudience(Audience), jwt.WithLeeway(10*time.Second))
	if _, err := parser.ParseWithClaims(raw, &claims, func(*jwt.Token) (any, error) { return s.public, nil }); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidAccessToken, err)
	}

	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return nil, fmt.Errorf("%w: subject is not a uuid", ErrInvalidAccessToken)
	}
	deviceID, err := uuid.Parse(claims.DeviceID)
	if err != nil {
		return nil, fmt.Errorf("%w: dev claim is not a uuid", ErrInvalidAccessToken)
	}
	return &Verified{UserID: userID, DeviceID: deviceID, TokenID: claims.ID}, nil
}

// JWKS returns the public verification key as a JWKS document, so the web client
// and the ownspce.com frontend can verify tokens without a shared secret.
func (s *Signer) JWKS() map[string]any {
	return map[string]any{"keys": []map[string]any{{"kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA", "kid": "ownspce-session-v1", "x": base64.RawURLEncoding.EncodeToString(s.public)}}}
}
