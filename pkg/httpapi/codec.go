package httpapi

import (
	"encoding/base64"
	"strings"
)

// decodeB64 accepts standard and URL-safe base64, padded or not, so clients on
// different platforms can use whatever their crypto library emits.
// Args: raw (encoded string), field (name used in the error message)
// Returns: decoded bytes, error
func decodeB64(raw, field string) ([]byte, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, badRequest("%s is required", field)
	}
	encodings := []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding}
	for _, enc := range encodings {
		if b, err := enc.DecodeString(trimmed); err == nil {
			return b, nil
		}
	}
	return nil, badRequest("%s is not valid base64", field)
}

// encodeB64 emits padded standard base64 for every binary field on the wire.
func encodeB64(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}

// encodeB64OrNil emits null rather than an empty string for absent binary.
//
// The difference matters where the client has to branch on it: an invite that
// carries no escrow public key means "this deployment cannot seal the household
// key for you, fall back", and a client checking truthiness of "" would get
// that right by accident while one checking `=== null` would not.
func encodeB64OrNil(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return base64.StdEncoding.EncodeToString(b)
}
