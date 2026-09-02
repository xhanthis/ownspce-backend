package auth

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/google/uuid"
)

func testGrants(t *testing.T) *UploadGrants {
	t.Helper()
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return NewUploadGrants(private)
}

func TestUploadGrantRoundTrips(t *testing.T) {
	grants := testGrants(t)
	space, attachment := uuid.New(), uuid.New()

	signature, expiresAt := grants.Sign(space, attachment, 2048, time.Minute)

	if err := grants.Verify(space, attachment, 2048, expiresAt, signature); err != nil {
		t.Fatalf("verify a freshly signed grant: %v", err)
	}
}

// A grant names one space, one attachment and one exact size. Widening any of
// them is what a stolen upload URL would try, so each must fail on its own.
func TestUploadGrantRejectsEveryAlteredField(t *testing.T) {
	grants := testGrants(t)
	space, attachment := uuid.New(), uuid.New()
	signature, expiresAt := grants.Sign(space, attachment, 2048, time.Minute)

	cases := map[string]struct {
		space, attachment uuid.UUID
		size, expiresAt   int64
		signature         string
	}{
		"another space":      {uuid.New(), attachment, 2048, expiresAt, signature},
		"another attachment": {space, uuid.New(), 2048, expiresAt, signature},
		"a larger body":      {space, attachment, 4096, expiresAt, signature},
		"a later expiry":     {space, attachment, 2048, expiresAt + 3600, signature},
		"a forged signature": {space, attachment, 2048, expiresAt, "AAAA"},
	}
	for name, c := range cases {
		if err := grants.Verify(c.space, c.attachment, c.size, c.expiresAt, c.signature); err == nil {
			t.Errorf("grant accepted with %s", name)
		}
	}
}

func TestUploadGrantExpires(t *testing.T) {
	grants := testGrants(t)
	space, attachment := uuid.New(), uuid.New()

	signature, expiresAt := grants.Sign(space, attachment, 2048, -time.Second)

	if err := grants.Verify(space, attachment, 2048, expiresAt, signature); err == nil {
		t.Fatal("an expired grant was accepted")
	}
}

// Two servers holding different session keys must not honour each other's URLs.
func TestUploadGrantIsKeyBound(t *testing.T) {
	first, second := testGrants(t), testGrants(t)
	space, attachment := uuid.New(), uuid.New()

	signature, expiresAt := first.Sign(space, attachment, 2048, time.Minute)

	if err := second.Verify(space, attachment, 2048, expiresAt, signature); err == nil {
		t.Fatal("a grant signed with another key was accepted")
	}
}
