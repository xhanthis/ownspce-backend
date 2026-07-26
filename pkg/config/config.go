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
	DatabaseURL      string
	JWTPrivateKey    ed25519.PrivateKey
	JWTPublicKey     ed25519.PublicKey
	GoogleClientIDs  []string
	AppleAudiences   []string
	BlobToken        string
	PublicSiteOrigin string
	Env              string
}

// Load reads configuration from the environment and validates what the API
// cannot run without.
// Returns: populated Config, or error naming the first missing/invalid variable.
// Handles: absent keys, malformed base64, wrong Ed25519 key sizes, empty
// provider audience lists (allowed — that provider is then simply refused).
func Load() (*Config, error) {
	c := &Config{
		DatabaseURL:      os.Getenv("DATABASE_URL"),
		GoogleClientIDs:  splitList(os.Getenv("GOOGLE_CLIENT_IDS")),
		BlobToken:        os.Getenv("BLOB_READ_WRITE_TOKEN"),
		PublicSiteOrigin: envOr("PUBLIC_SITE_ORIGIN", "https://ownspce.com"),
		Env:              envOr("ENV", "development"),
	}
	c.AppleAudiences = splitList(strings.Join([]string{os.Getenv("APPLE_BUNDLE_ID"), os.Getenv("APPLE_SERVICES_ID")}, ","))

	if c.DatabaseURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
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
