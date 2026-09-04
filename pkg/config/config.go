// Package config loads and validates process configuration from the environment.
package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

type Config struct {
	DatabaseURL     string
	JWTPrivateKey   ed25519.PrivateKey
	JWTPublicKey    ed25519.PublicKey
	GoogleClientIDs []string
	AppleAudiences  []string
	BlobToken       string
	AutosendAPIKey  string
	// EscrowMasterKey seals the per-account escrow private keys at rest. Without
	// it the API runs, but nobody can recover an account by email — which is a
	// refusal rather than a silent downgrade.
	EscrowMasterKey  []byte
	EmailFromAddress string
	EmailFromName    string
	PublicSiteOrigin string
	AllowedOrigins   []string
	// SessionCookieDomain is the parent domain the cross-surface session cookie
	// is scoped to, e.g. "ownspce.com" — which covers app., money. and every
	// other subdomain. Empty disables the cookie entirely, which is the right
	// answer for local development and for any deployment whose surfaces do not
	// share a registrable domain: without one, every surface simply asks for its
	// own sign-in.
	//
	// A leading dot is accepted and stripped. RFC 6265 says a browser ignores it
	// and stores the cookie against the bare domain either way, so keeping it
	// would only mean this field never equalled what a parsed cookie reports.
	SessionCookieDomain string
	// SessionOrigins are the surfaces allowed to hold and spend that cookie:
	// app.ownspce.com and money.ownspce.com, and nothing else.
	//
	// Deliberately a shorter list than AllowedOrigins rather than the same one.
	// The CORS allowlist has to contain the marketing origin, and that origin is
	// also where published pages — HTML somebody else wrote — are served from. A
	// cookie the browser attaches to a same-site request, plus an endpoint that
	// mints a device from it, would turn one XSS there into an attacker's own
	// device sitting on somebody's account with every space key re-wrapped for
	// it. Reading the response would not even be needed; the write is the
	// damage. So the credentialed path gets its own, minimal list.
	//
	// Empty disables the cross-surface session entirely, exactly as an empty
	// SessionCookieDomain does — an operator has to name the app surfaces on
	// purpose.
	SessionOrigins []string
	Env            string
}

// Load reads configuration from the environment and validates what the API
// cannot run without.
// Returns: populated Config, or error naming the first missing/invalid variable.
// Handles: absent keys, malformed base64, wrong Ed25519 key sizes, empty
// provider audience lists (allowed — that provider is then simply refused).
func Load() (*Config, error) {
	c := &Config{
		DatabaseURL:         os.Getenv("DATABASE_URL"),
		GoogleClientIDs:     splitList(os.Getenv("GOOGLE_CLIENT_IDS")),
		BlobToken:           os.Getenv("BLOB_READ_WRITE_TOKEN"),
		AutosendAPIKey:      os.Getenv("AUTOSEND_API_KEY"),
		EmailFromAddress:    envOr("EMAIL_FROM_ADDRESS", "hello@ownspce.com"),
		EmailFromName:       envOr("EMAIL_FROM_NAME", "OwnSpce"),
		PublicSiteOrigin:    envOr("PUBLIC_SITE_ORIGIN", "https://ownspce.com"),
		SessionCookieDomain: strings.TrimPrefix(strings.TrimSpace(os.Getenv("SESSION_COOKIE_DOMAIN")), "."),
		SessionOrigins:      splitList(os.Getenv("SESSION_ORIGINS")),
		Env:                 envOr("ENV", "development"),
	}
	c.AppleAudiences = splitList(strings.Join([]string{os.Getenv("APPLE_BUNDLE_ID"), os.Getenv("APPLE_SERVICES_ID")}, ","))
	c.AllowedOrigins = mergeOrigins(c.PublicSiteOrigin, splitList(os.Getenv("ALLOWED_ORIGINS")))
	c.SessionOrigins = mergeOrigins("", c.SessionOrigins)

	if c.DatabaseURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}

	if raw := os.Getenv("ESCROW_MASTER_KEY"); raw != "" {
		key, err := decodeKey("ESCROW_MASTER_KEY", 32)
		if err != nil {
			return nil, err
		}
		c.EscrowMasterKey = key
	}

	priv, err := decodeKey("JWT_PRIVATE_KEY", ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	c.JWTPrivateKey = ed25519.NewKeyFromSeed(priv)

	if raw := os.Getenv("JWT_PUBLIC_KEY"); raw != "" {
		pub, err := decodeKey("JWT_PUBLIC_KEY", ed25519.PublicKeySize)
		if err != nil {
			return nil, err
		}
		if !ed25519.PublicKey(pub).Equal(c.JWTPrivateKey.Public()) {
			return nil, fmt.Errorf("JWT_PUBLIC_KEY does not match JWT_PRIVATE_KEY")
		}
		c.JWTPublicKey = pub
	} else {
		c.JWTPublicKey = c.JWTPrivateKey.Public().(ed25519.PublicKey)
	}

	return c, nil
}

func (c *Config) IsProduction() bool { return c.Env == "production" }

// SessionOriginAllowed reports whether an origin may hold or spend the
// cross-surface session cookie.
//
// Separate from originAllowed on purpose — see SessionOrigins for why the
// marketing origin must not be on this list. Outside production any localhost
// origin passes, so a local Vite server and a local Next server can exercise
// the handoff between them.
// Args: origin (the browser's Origin header, exactly as sent)
// Returns: true when this origin is a designated app surface
func (c *Config) SessionOriginAllowed(origin string) bool {
	if origin == "" {
		return false
	}
	for _, allowed := range c.SessionOrigins {
		if origin == allowed {
			return true
		}
	}
	return !c.IsProduction() && strings.HasPrefix(origin, "http://localhost")
}

func decodeKey(name string, want int) ([]byte, error) {
	raw := os.Getenv(name)
	if raw == "" {
		return nil, fmt.Errorf("%s is required", name)
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("%s is not valid base64: %w", name, err)
	}
	if len(b) != want {
		return nil, fmt.Errorf("%s must decode to %d bytes, got %d", name, want, len(b))
	}
	return b, nil
}

// mergeOrigins builds the browser origin allowlist: the public site plus any
// extra origins from ALLOWED_ORIGINS (the web app at app.ownspce.com, for
// example), deduplicated and with trailing slashes trimmed so a config typo
// does not silently fail every preflight.
// Args: primary (PUBLIC_SITE_ORIGIN), extra (parsed ALLOWED_ORIGINS)
// Returns: the deduplicated allowlist, primary first.
func mergeOrigins(primary string, extra []string) []string {
	seen := make(map[string]bool, len(extra)+1)
	var out []string
	for _, origin := range append([]string{primary}, extra...) {
		normalized := strings.TrimSuffix(strings.TrimSpace(origin), "/")
		if normalized == "" || seen[normalized] {
			continue
		}
		seen[normalized] = true
		out = append(out, normalized)
	}
	return out
}

func splitList(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if v := strings.TrimSpace(part); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
