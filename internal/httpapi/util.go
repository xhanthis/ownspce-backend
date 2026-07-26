package httpapi

import (
	"context"
	"crypto/sha256"
	"net/http"
	"net/url"
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
