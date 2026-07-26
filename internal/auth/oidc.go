// Package auth verifies third-party sign-in tokens and issues Ownspce's own
// session tokens. Auth identity decides what a user may FETCH; it never grants
// the ability to DECRYPT anything, which depends solely on device-held keys.
package auth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	ProviderGoogle = "google"
	ProviderApple  = "apple"

	googleIssuerA = "https://accounts.google.com"
	googleIssuerB = "accounts.google.com"
	appleIssuer   = "https://appleid.apple.com"

	googleJWKSURL = "https://www.googleapis.com/oauth2/v3/certs"
	appleJWKSURL  = "https://appleid.apple.com/auth/keys"
)

var (
	ErrUnsupportedProvider = errors.New("auth: unsupported provider")
	ErrInvalidIDToken      = errors.New("auth: invalid id token")
	ErrEmailUnverified     = errors.New("auth: provider did not verify the email address")
	ErrAudienceMismatch    = errors.New("auth: id token audience is not an allowed client id")
	ErrNoAudienceConfigured = errors.New("auth: no client ids configured for provider")
)

// Identity is the verified result of a provider sign-in.
type Identity struct {
	Provider  string
	Subject   string
	Email     string
	Name      string
	AvatarURL string
}

// Verifier validates Google and Apple ID tokens against the providers' JWKS.
type Verifier struct {
	GoogleClientIDs []string
	AppleAudiences  []string

	keys         *jwksCache
	googleJWKS   string
	appleJWKS    string
	extraIssuers []string
}

func NewVerifier(googleClientIDs, appleAudiences []string) *Verifier {
	return &Verifier{GoogleClientIDs: googleClientIDs, AppleAudiences: appleAudiences, keys: newJWKSCache(), googleJWKS: googleJWKSURL, appleJWKS: appleJWKSURL}
}

// Verify checks an ID token's signature, issuer, audience, expiry, and email
// verification flag.
// Args: ctx, provider ("google"|"apple"), rawToken
// Returns: verified Identity, error
// Handles: unknown provider, unconfigured audiences, rotated signing keys (JWKS
// refetched once on unknown kid), unverified email, wrong audience or issuer
func (v *Verifier) Verify(ctx context.Context, provider, rawToken string) (*Identity, error) {
	var (
		jwksURL   string
		issuers   []string
		audiences []string
	)
	switch provider {
	case ProviderGoogle:
		jwksURL, issuers, audiences = v.googleJWKS, []string{googleIssuerA, googleIssuerB}, v.GoogleClientIDs
	case ProviderApple:
		jwksURL, issuers, audiences = v.appleJWKS, []string{appleIssuer}, v.AppleAudiences
	default:
		return nil, ErrUnsupportedProvider
	}
	issuers = append(issuers, v.extraIssuers...)
	if len(audiences) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrNoAudienceConfigured, provider)
	}

	var claims struct {
		jwt.RegisteredClaims
		Email         string `json:"email"`
		EmailVerified any    `json:"email_verified"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
	}

	keyFunc := func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("id token has no kid header")
		}
		return v.keys.publicKey(ctx, jwksURL, kid)
	}

	parser := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}), jwt.WithExpirationRequired(), jwt.WithLeeway(30*time.Second))
	if _, err := parser.ParseWithClaims(rawToken, &claims, keyFunc); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidIDToken, err)
	}

	if !contains(issuers, claims.Issuer) {
		return nil, fmt.Errorf("%w: issuer %q", ErrInvalidIDToken, claims.Issuer)
	}
	if !audienceAllowed(claims.Audience, audiences) {
		return nil, ErrAudienceMismatch
	}
	if claims.Subject == "" {
		return nil, fmt.Errorf("%w: empty subject", ErrInvalidIDToken)
	}
	if claims.Email == "" {
		return nil, fmt.Errorf("%w: no email claim", ErrInvalidIDToken)
	}
	if !truthy(claims.EmailVerified) {
		return nil, ErrEmailUnverified
	}

	return &Identity{Provider: provider, Subject: claims.Subject, Email: normalizeEmail(claims.Email), Name: claims.Name, AvatarURL: claims.Picture}, nil
}

// jwksCache caches provider signing keys in process memory. Serverless instances
// are short-lived, so this is a per-instance cache with a hard TTL plus a single
// forced refresh when an unknown key id appears (provider key rotation).
type jwksCache struct {
	mu     sync.Mutex
	http   *http.Client
	byURL  map[string]map[string]*rsa.PublicKey
	loaded map[string]time.Time
}

func newJWKSCache() *jwksCache {
	return &jwksCache{http: &http.Client{Timeout: 5 * time.Second}, byURL: map[string]map[string]*rsa.PublicKey{}, loaded: map[string]time.Time{}}
}

const jwksTTL = 12 * time.Hour

func (c *jwksCache) publicKey(ctx context.Context, url, kid string) (*rsa.PublicKey, error) {
	c.mu.Lock()
	keys, ok := c.byURL[url]
	fresh := ok && time.Since(c.loaded[url]) < jwksTTL
	c.mu.Unlock()

	if fresh {
		if key, ok := keys[kid]; ok {
			return key, nil
		}
	}

	refreshed, err := c.fetch(ctx, url)
	if err != nil {
		if key, ok := keys[kid]; ok {
			return key, nil
		}
		return nil, err
	}
	key, ok := refreshed[kid]
	if !ok {
		return nil, fmt.Errorf("no signing key %q at %s", kid, url)
	}
	return key, nil
}

func (c *jwksCache) fetch(ctx context.Context, url string) (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch jwks: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	var doc struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("decode jwks: %w", err)
	}

	keys := map[string]*rsa.PublicKey{}
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || k.Kid == "" {
			continue
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			continue
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			continue
		}
		keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(new(big.Int).SetBytes(eBytes).Int64())}
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("jwks at %s contained no usable RSA keys", url)
	}

	c.mu.Lock()
	c.byURL[url] = keys
	c.loaded[url] = time.Now()
	c.mu.Unlock()
	return keys, nil
}

func audienceAllowed(aud jwt.ClaimStrings, allowed []string) bool {
	for _, a := range aud {
		if contains(allowed, a) {
			return true
		}
	}
	return false
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// truthy accepts both the boolean and stringified forms of email_verified, since
// Apple sends "true" as a string.
func truthy(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t == "true"
	default:
		return false
	}
}

func normalizeEmail(email string) string {
	out := make([]byte, 0, len(email))
	for i := 0; i < len(email); i++ {
		ch := email[i]
		if ch >= 'A' && ch <= 'Z' {
			ch += 'a' - 'A'
		}
		out = append(out, ch)
	}
	return string(out)
}
