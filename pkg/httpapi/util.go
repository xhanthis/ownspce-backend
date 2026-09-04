package httpapi

import (
	"context"
	"crypto/sha256"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// blobHostSuffix is the only host the API will accept or store a blob pointer for,
// so a client cannot make the server record or serve an arbitrary external URL.
const blobHostSuffix = ".blob.vercel-storage.com"

// isOwnBlobURL reports whether a URL is a Vercel Blob object belonging to this
// project's store.
func isOwnBlobURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Path == "" || parsed.Path == "/" {
		return false
	}
	return strings.HasSuffix(parsed.Host, blobHostSuffix)
}

// emailPattern is a deliberately loose shape check. Proving an address exists is
// the code's job; this only rejects what could never be one, so a valid address
// with an unusual local part is never turned away at the door.
var emailPattern = regexp.MustCompile(`^[^@\s]+@[^@\s.]+(\.[^@\s.]+)+$`)

// validEmail reports whether a string is plausibly an email address, under the
// 254-byte limit RFC 5321 puts on one.
func validEmail(raw string) bool {
	trimmed := strings.TrimSpace(raw)
	return len(trimmed) <= 254 && emailPattern.MatchString(trimmed)
}

// oneOf reports whether value is one of the allowed enum members. Used to reject
// a value the database CHECK constraint would refuse, so the caller gets a clear
// 400 rather than a 500 from a constraint violation.
func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

// detachedContext gives fire-and-forget cleanup work a deadline of its own, since
// the request context is cancelled the moment the response is written.
func detachedContext() context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	go func() {
		<-ctx.Done()
		cancel()
	}()
	return ctx
}

// hashIP one-way hashes a client IP so abuse reports can be deduplicated without
// storing addresses.
func hashIP(r *http.Request) []byte {
	sum := sha256.Sum256([]byte(clientIP(r)))
	return sum[:]
}
