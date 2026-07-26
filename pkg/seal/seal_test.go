package seal

import (
	"errors"
	"testing"
)

func TestValidateCiphertextAcceptsEveryBucket(t *testing.T) {
	for _, bucket := range Buckets {
		payload := make([]byte, bucket+AEADOverhead)

		got, err := ValidateCiphertext(payload)

		if err != nil {
			t.Errorf("bucket %d: unexpected error %v", bucket, err)
		}
		if got != bucket {
			t.Errorf("bucket %d: reported %d", bucket, got)
		}
	}
}

func TestValidateCiphertextRejectsUnpaddedSizes(t *testing.T) {
	cases := map[string]int{
		"one byte under a bucket": Buckets[0] + AEADOverhead - 1,
		"one byte over a bucket":  Buckets[0] + AEADOverhead + 1,
		"raw bucket with no aead": Buckets[1],
		"over the largest bucket": Buckets[len(Buckets)-1] + AEADOverhead + 1,
	}

	for name, size := range cases {
		if _, err := ValidateCiphertext(make([]byte, size)); !errors.Is(err, ErrBucketViolation) {
			t.Errorf("%s (%d bytes): expected ErrBucketViolation, got %v", name, size, err)
		}
	}
}

func TestValidateCiphertextRejectsEmpty(t *testing.T) {
	if _, err := ValidateCiphertext(nil); !errors.Is(err, ErrEmpty) {
		t.Fatalf("expected ErrEmpty, got %v", err)
	}
}

func TestValidatePublicKeyEnforcesX25519Size(t *testing.T) {
	if err := ValidatePublicKey(make([]byte, PublicKeySize)); err != nil {
		t.Fatalf("expected 32 bytes to be valid: %v", err)
	}
	for _, size := range []int{0, 31, 33, 64} {
		if err := ValidatePublicKey(make([]byte, size)); !errors.Is(err, ErrKeySize) {
			t.Errorf("size %d: expected ErrKeySize, got %v", size, err)
		}
	}
}

func TestValidateWrappedKeyBounds(t *testing.T) {
	if err := ValidateWrappedKey(make([]byte, 80)); err != nil {
		t.Fatalf("expected a sealed-box sized key to be valid: %v", err)
	}
	for _, size := range []int{0, MinWrappedKeySize - 1, MaxWrappedKeySize + 1} {
		if err := ValidateWrappedKey(make([]byte, size)); !errors.Is(err, ErrKeySize) {
			t.Errorf("size %d: expected ErrKeySize, got %v", size, err)
		}
	}
}

func TestMaxCiphertextMatchesLargestBucket(t *testing.T) {
	want := Buckets[len(Buckets)-1] + AEADOverhead
	if MaxCiphertext != want {
		t.Fatalf("MaxCiphertext = %d, want %d — the database CHECK constraint must match", MaxCiphertext, want)
	}
}
