// Package blob wraps the Vercel Blob HTTP API for the two payload classes that
// outgrow a Postgres column: large sealed snapshots (opaque ciphertext) and
// published page assets (deliberately public). Object paths are random UUIDs —
// never derived from a title, slug, or space id — so a listing leaks nothing.
package blob

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
)

const apiBase = "https://blob.vercel-storage.com"

// ErrNotConfigured is returned when no blob token is present, so routes that
// need object storage can answer 503 instead of failing obscurely.
var ErrNotConfigured = errors.New("blob: BLOB_READ_WRITE_TOKEN is not configured")

type Client struct {
	token string
	http  *http.Client
}

func New(token string) *Client {
	return &Client{token: token, http: &http.Client{Timeout: 8 * time.Second}}
}

func (c *Client) Configured() bool { return c.token != "" }

// RandomPath builds an opaque object path under a prefix.
// Args: prefix ("snapshots", "pages", "assets"), ext (".bin", ".html", …)
// Returns: e.g. "snapshots/9f1c….bin"
func RandomPath(prefix, ext string) string {
	return fmt.Sprintf("%s/%s%s", prefix, uuid.NewString(), ext)
}

// Put uploads bytes and returns the object's public URL.
// Args: ctx, pathname (opaque, from RandomPath), contentType, body,
// cacheMaxAge (seconds; 0 for no explicit cache header)
// Returns: object URL, error
// Handles: missing token (ErrNotConfigured), non-2xx responses (body included in
// the error for diagnosis)
func (c *Client) Put(ctx context.Context, pathname, contentType string, body []byte, cacheMaxAge int) (string, error) {
	if !c.Configured() {
		return "", ErrNotConfigured
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, apiBase+"/"+pathname, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("authorization", "Bearer "+c.token)
	req.Header.Set("x-api-version", "7")
	req.Header.Set("x-content-type", contentType)
	req.Header.Set("x-add-random-suffix", "0")
	req.Header.Set("content-type", contentType)
	if cacheMaxAge > 0 {
		req.Header.Set("x-cache-control-max-age", fmt.Sprintf("%d", cacheMaxAge))
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("blob put: %w", err)
	}
	defer resp.Body.Close()

	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("blob put: status %d: %s", resp.StatusCode, string(payload))
	}

	var out struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(payload, &out); err != nil {
		return "", fmt.Errorf("blob put: decode response: %w", err)
	}
	if out.URL == "" {
		return "", errors.New("blob put: response contained no url")
	}
	return out.URL, nil
}

// Delete removes objects, ignoring ones that are already gone.
// Args: ctx, urls
// Returns: error (nil for an empty list or an unconfigured client, since deletion
// is always best-effort cleanup)
func (c *Client) Delete(ctx context.Context, urls []string) error {
	if len(urls) == 0 || !c.Configured() {
		return nil
	}

	payload, err := json.Marshal(map[string][]string{"urls": urls})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+"/delete", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("authorization", "Bearer "+c.token)
	req.Header.Set("x-api-version", "7")
	req.Header.Set("content-type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("blob delete: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("blob delete: status %d", resp.StatusCode)
	}
	return nil
}
