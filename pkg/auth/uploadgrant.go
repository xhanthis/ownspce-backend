package auth

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ErrGrantInvalid covers every rejection of an upload grant — bad signature,
// expired, or altered parameters. The reasons are deliberately not distinguished
// on the wire, so a caller cannot probe which part of a forged URL was wrong.
var ErrGrantInvalid = errors.New("auth: upload grant is not valid")

// UploadGrants mints and checks the short-lived signatures that authorize a
// single attachment upload.
//
// Attachments are PUT straight at the API by a plain fetch that carries no
// Authorization header — the sealed bytes are too large to route through a JSON
// request and the client has no session to attach to a raw upload. The URL is
// therefore the credential: it names exactly one space, one attachment id and
// one byte count, and it stops working within minutes. Widening any of those
// invalidates the signature.
type UploadGrants struct {
	key []byte
}

// NewUploadGrants derives the signing key from the session key's seed, so no
// additional secret has to be provisioned or rotated separately.
func NewUploadGrants(private ed25519.PrivateKey) *UploadGrants {
	sum := sha256.Sum256(append([]byte("ownspce/upload-grant/v1"), private.Seed()...))
	return &UploadGrants{key: sum[:]}
}

func (g *UploadGrants) mac(spaceID, attachmentID uuid.UUID, size, expiresAt int64) string {
	h := hmac.New(sha256.New, g.key)
	fmt.Fprintf(h, "%s\n%s\n%d\n%d", spaceID, attachmentID, size, expiresAt)
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// Sign issues a grant for one upload.
// Args: spaceID, attachmentID, size (exact sealed byte count), ttl
// Returns: the signature and the unix expiry to put in the URL
func (g *UploadGrants) Sign(spaceID, attachmentID uuid.UUID, size int64, ttl time.Duration) (string, int64) {
	expiresAt := time.Now().Add(ttl).Unix()
	return g.mac(spaceID, attachmentID, size, expiresAt), expiresAt
}

// Verify checks a grant presented on an upload.
// Args: spaceID, attachmentID, size (the body length actually received), expiresAt, signature
// Returns: ErrGrantInvalid on expiry or any mismatch, nil when the upload may proceed
// Handles: a body that does not match the signed size, which is what stops a
// grant for a small file being reused to store a large one
func (g *UploadGrants) Verify(spaceID, attachmentID uuid.UUID, size, expiresAt int64, signature string) error {
	if time.Now().Unix() > expiresAt {
		return ErrGrantInvalid
	}
	if !hmac.Equal([]byte(signature), []byte(g.mac(spaceID, attachmentID, size, expiresAt))) {
		return ErrGrantInvalid
	}
	return nil
}
