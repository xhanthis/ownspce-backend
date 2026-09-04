// Package seal holds the only knowledge the server has about ciphertext: its
// permitted SHAPE. Clients pad plaintext into fixed buckets before encrypting so
// stored sizes leak nothing about content length; the server enforces that
// padding by rejecting any ciphertext whose length is not a bucket plus AEAD
// overhead. Nothing here decrypts, parses, or inspects payload bytes.
package seal

import (
	"errors"
	"fmt"
)

// AEADOverhead is the XChaCha20-Poly1305 nonce (24B) plus authentication tag (16B).
const AEADOverhead = 40

// Buckets are the permitted padded plaintext sizes.
var Buckets = []int{1024, 4096, 16384, 65536, 262144}

// MaxCiphertext is the largest ciphertext accepted in a database column.
var MaxCiphertext = Buckets[len(Buckets)-1] + AEADOverhead

// PublicKeySize is the X25519 public key length.
const PublicKeySize = 32

// WrappedKey size bounds for a libsodium sealed box of a 32-byte space key:
// 32B ephemeral public key + 32B key + 16B tag = 80B. The range stays loose
// enough to allow a versioned envelope prefix.
const (
	MinWrappedKeySize = 48
	MaxWrappedKeySize = 256
)

var (
	ErrBucketViolation = errors.New("seal: ciphertext length is not a padded bucket")
	ErrEmpty           = errors.New("seal: ciphertext is empty")
	ErrKeySize         = errors.New("seal: unexpected key size")
)

// ValidateCiphertext checks that a sealed payload matches one of the padding
// buckets, which is the server's entire content-related validation surface.
// Args: b (ciphertext bytes)
// Returns: the bucket size it matched, or ErrBucketViolation / ErrEmpty
func ValidateCiphertext(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, ErrEmpty
	}
	for _, bucket := range Buckets {
		if len(b) == bucket+AEADOverhead {
			return bucket, nil
		}
	}
	return 0, fmt.Errorf("%w: got %d bytes, want one of %v plus %d", ErrBucketViolation, len(b), Buckets, AEADOverhead)
}

// ValidatePublicKey checks an X25519 public key length.
func ValidatePublicKey(b []byte) error {
	if len(b) != PublicKeySize {
		return fmt.Errorf("%w: public key must be %d bytes, got %d", ErrKeySize, PublicKeySize, len(b))
	}
	return nil
}

// ValidateWrappedKey checks a sealed-box-wrapped space key length.
func ValidateWrappedKey(b []byte) error {
	if len(b) < MinWrappedKeySize || len(b) > MaxWrappedKeySize {
		return fmt.Errorf("%w: wrapped key must be %d-%d bytes, got %d", ErrKeySize, MinWrappedKeySize, MaxWrappedKeySize, len(b))
	}
	return nil
}

// MoneyBuckets are the padding buckets for a Kosh ledger record.
//
// The Tier 2 ladder starts at 1 KiB, which is right for a note body and wrong
// for a ledger row: an expense is a handful of numbers and a short note, and a
// household with five thousand entries would pay five megabytes to say so. The
// money ladder starts at 256 bytes instead — still far above the entropy of a
// single entry, so the stored length keeps revealing nothing, and small enough
// that a year of a family's spending fits in one page load.
var MoneyBuckets = []int{256, 1024, 4096}

// MaxMoneyCiphertext is the largest sealed money record accepted.
var MaxMoneyCiphertext = MoneyBuckets[len(MoneyBuckets)-1] + AEADOverhead

// ValidateMoneyCiphertext checks a sealed money record against the money ladder.
// Args: b (ciphertext bytes)
// Returns: the bucket size it matched, or ErrBucketViolation / ErrEmpty
func ValidateMoneyCiphertext(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, ErrEmpty
	}
	for _, bucket := range MoneyBuckets {
		if len(b) == bucket+AEADOverhead {
			return bucket, nil
		}
	}
	return 0, fmt.Errorf("%w: got %d bytes, want one of %v plus %d", ErrBucketViolation, len(b), MoneyBuckets, AEADOverhead)
}
