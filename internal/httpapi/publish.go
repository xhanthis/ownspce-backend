package httpapi

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/ownspce/backend/internal/blob"
	"github.com/ownspce/backend/internal/store"
)

// Publishing limits. This is the only readable content on the server, so it is
// also the only surface with size and volume caps and moderation.
const (
	maxHTMLBytes      = 2 << 20
	maxBlocksBytes    = 2 << 20
	maxAssetsPerPage  = 25
	maxPublishedPages = 20
	maxOGTitle        = 200
	maxOGDescription  = 400
	publicCacheTTL    = 60
)

var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

var allowedAssetTypes = map[string]string{"image/png": ".png", "image/jpeg": ".jpg", "image/webp": ".webp", "image/gif": ".gif", "image/svg+xml": ".svg"}

type publishRequest struct {
	Slug          string   `json:"slug"`
	HTML          string   `json:"html"`
	Blocks        string   `json:"blocks"`
	AssetURLs     []string `json:"assetUrls"`
	OGTitle       string   `json:"ogTitle"`
	OGDescription string   `json:"ogDescription"`
}

// handlePublish stores a page the client already decrypted and rendered. This is
// the deliberate exception to zero knowledge: the user asked for this one page to
// be public, so plaintext HTML and block JSON are uploaded to a public store.
// Everything else in the account stays sealed.
// Handles: missing username (a publish URL needs an @handle), reserved or malformed
// slugs, per-plan page quota, oversized payloads, republish (old blobs cleaned up).
func (s *Server) handlePublish(w http.ResponseWriter, r *http.Request) {
	if !s.blob.Configured() {
		writeError(w, errUnavailable("publishing requires object storage, which is not configured"))
		return
	}

	var req publishRequest
	if err := decodeJSON(w, r, maxPublishBody, &req); err != nil {
		writeError(w, err)
		return
	}

	slug := strings.ToLower(strings.TrimSpace(req.Slug))
	if !slugPattern.MatchString(slug) {
		writeError(w, badRequest("slug must be 1-64 characters of a-z, 0-9 or hyphen, starting alphanumeric"))
		return
	}
	if len(req.OGTitle) > maxOGTitle || len(req.OGDescription) > maxOGDescription {
		writeError(w, badRequest("ogTitle must be under %d and ogDescription under %d characters", maxOGTitle, maxOGDescription))
		return
	}
	if len(req.AssetURLs) > maxAssetsPerPage {
		writeError(w, badRequest("a page may reference at most %d uploaded assets", maxAssetsPerPage))
		return
	}
	for _, u := range req.AssetURLs {
		if !isOwnBlobURL(u) {
			writeError(w, badRequest("assetUrls must be URLs returned by POST /publish/assets"))
			return
		}
	}

	html, err := decodeB64(req.HTML, "html")
	if err != nil {
		writeError(w, err)
		return
	}
	blocks, err := decodeB64(req.Blocks, "blocks")
	if err != nil {
		writeError(w, err)
		return
	}
	if len(html) > maxHTMLBytes || len(blocks) > maxBlocksBytes {
		writeError(w, errTooLarge("payload_too_large", fmt.Sprintf("html must be under %d bytes and blocks under %d bytes", maxHTMLBytes, maxBlocksBytes)))
		return
	}

	c := callerFrom(r.Context())
	user, err := s.store.GetUser(r.Context(), c.UserID)
	if err != nil {
		writeError(w, err)
		return
	}
	if user.Username == nil || *user.Username == "" {
		writeError(w, badRequest("set a username with PATCH /me before publishing — the page URL is /@username/slug"))
		return
	}

	reserved, err := s.store.IsReservedName(r.Context(), slug)
	if err != nil {
		writeError(w, err)
		return
	}
	if reserved {
		writeError(w, errConflict("slug_reserved", "that slug is reserved"))
		return
	}

	existing, err := s.store.ListPublishes(r.Context(), c.UserID)
	if err != nil {
		writeError(w, err)
		return
	}
	isReplacement := false
	for _, p := range existing {
		if strings.EqualFold(p.Slug, slug) {
			isReplacement = true
			break
		}
	}
	if !isReplacement && len(existing) >= maxPublishedPages {
		writeError(w, errForbidden("publish_limit", fmt.Sprintf("this plan allows %d published pages", maxPublishedPages)))
		return
	}

	htmlURL, err := s.blob.Put(r.Context(), blob.RandomPath("pages", ".html"), "text/html; charset=utf-8", html, publicCacheTTL)
	if err != nil {
		writeError(w, err)
		return
	}
	blocksURL, err := s.blob.Put(r.Context(), blob.RandomPath("pages", ".json"), "application/json; charset=utf-8", blocks, publicCacheTTL)
	if err != nil {
		go func() { _ = s.blob.Delete(detachedContext(), []string{htmlURL}) }()
		writeError(w, err)
		return
	}

	published, stale, err := s.store.UpsertPublish(r.Context(), c.UserID, slug, htmlURL, blocksURL, req.AssetURLs, req.OGTitle, req.OGDescription, int64(len(html)+len(blocks)))
	if err != nil {
		writeError(w, err)
		return
	}
	if len(stale) > 0 {
		go func(urls []string) {
			if err := s.blob.Delete(detachedContext(), urls); err != nil {
				log.Printf("delete superseded publish blobs: %v", err)
			}
		}(stale)
	}

	writeJSON(w, http.StatusOK, map[string]any{"url": fmt.Sprintf("%s/@%s/%s", s.cfg.PublicSiteOrigin, *user.Username, slug), "slug": slug, "publishedAt": published.PublishedAt.UTC().Format(time.RFC3339), "updatedAt": published.UpdatedAt.UTC().Format(time.RFC3339)})
}

// handlePublishAsset uploads one image for a published page. Content type comes
// from an allowlist so the public store never serves arbitrary file types.
func (s *Server) handlePublishAsset(w http.ResponseWriter, r *http.Request) {
	if !s.blob.Configured() {
		writeError(w, errUnavailable("publishing requires object storage, which is not configured"))
		return
	}

	contentType := strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0])
	ext, ok := allowedAssetTypes[contentType]
	if !ok {
		writeError(w, badRequest("Content-Type must be one of png, jpeg, webp, gif or svg"))
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxAssetBody)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeError(w, errTooLarge("payload_too_large", fmt.Sprintf("assets must be under %d bytes", maxAssetBody)))
			return
		}
		writeError(w, err)
		return
	}
	if len(body) == 0 {
		writeError(w, badRequest("asset body is empty"))
		return
	}

	url, err := s.blob.Put(r.Context(), blob.RandomPath("assets", ext), contentType, body, 31536000)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"url": url, "sizeBytes": len(body)})
}

func (s *Server) handleListPublishes(w http.ResponseWriter, r *http.Request) {
	c := callerFrom(r.Context())
	user, err := s.store.GetUser(r.Context(), c.UserID)
	if err != nil {
		writeError(w, err)
		return
	}

	pages, err := s.store.ListPublishes(r.Context(), c.UserID)
	if err != nil {
		writeError(w, err)
		return
	}

	username := ""
	if user.Username != nil {
		username = *user.Username
	}
	out := make([]map[string]any, 0, len(pages))
	for _, p := range pages {
		out = append(out, map[string]any{"slug": p.Slug, "url": fmt.Sprintf("%s/@%s/%s", s.cfg.PublicSiteOrigin, username, p.Slug), "status": p.Status, "sizeBytes": p.SizeBytes, "ogTitle": p.OGTitle, "publishedAt": p.PublishedAt.UTC().Format(time.RFC3339), "updatedAt": p.UpdatedAt.UTC().Format(time.RFC3339)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"pages": out})
}

// handleUnpublish removes a page and deletes its blobs, so the only readable copy
// on the server disappears.
func (s *Server) handleUnpublish(w http.ResponseWriter, r *http.Request) {
	slug := strings.ToLower(strings.TrimSpace(chi.URLParam(r, "slug")))
	if !slugPattern.MatchString(slug) {
		writeError(w, errNotFound("no such published page"))
		return
	}

	urls, err := s.store.DeletePublish(r.Context(), callerFrom(r.Context()).UserID, slug)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, errNotFound("no such published page"))
			return
		}
		writeError(w, err)
		return
	}

	if len(urls) > 0 {
		go func(targets []string) {
			if err := s.blob.Delete(detachedContext(), targets); err != nil {
				log.Printf("delete unpublished blobs: %v", err)
			}
		}(urls)
	}
	w.WriteHeader(http.StatusNoContent)
}

// handlePublicPage resolves @username/slug for the ownspce.com serving route,
// which fetches the HTML blob and renders it with Open Graph tags.
// Handles: unknown page (404), moderated page (451).
func (s *Server) handlePublicPage(w http.ResponseWriter, r *http.Request) {
	username := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(chi.URLParam(r, "username")), "@"))
	slug := strings.ToLower(strings.TrimSpace(chi.URLParam(r, "slug")))
	if !usernamePattern.MatchString(username) || !slugPattern.MatchString(slug) {
		writeError(w, errNotFound("no such published page"))
		return
	}

	page, err := s.store.GetPublicPage(r.Context(), username, slug)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrForbidden):
			writeError(w, apiError{status: http.StatusUnavailableForLegalReasons, Code: "taken_down", Message: "this page has been removed"})
		case errors.Is(err, store.ErrNotFound):
			writeError(w, errNotFound("no such published page"))
		default:
			writeError(w, err)
		}
		return
	}

	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d, stale-while-revalidate=300", publicCacheTTL))
	writeJSON(w, http.StatusOK, map[string]any{"username": page.Username, "slug": page.Slug, "htmlUrl": page.HTMLBlobURL, "blocksUrl": page.BlocksBlobURL, "assetUrls": page.AssetBlobURLs, "ogTitle": page.OGTitle, "ogDescription": page.OGDescription, "publishedAt": page.PublishedAt.UTC().Format(time.RFC3339), "updatedAt": page.UpdatedAt.UTC().Format(time.RFC3339)})
}

type reportRequest struct {
	Reason  string `json:"reason"`
	Details string `json:"details"`
}

// handlePublicReport records an abuse report against a published page. Published
// pages are the only readable content, so this is the whole moderation intake;
// takedown itself is an operator action that flips publishes.status.
func (s *Server) handlePublicReport(w http.ResponseWriter, r *http.Request) {
	username := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(chi.URLParam(r, "username")), "@"))
	slug := strings.ToLower(strings.TrimSpace(chi.URLParam(r, "slug")))

	var req reportRequest
	if err := decodeJSON(w, r, maxSmallBody, &req); err != nil {
		writeError(w, err)
		return
	}
	if len(req.Reason) > 200 || len(req.Details) > 2000 {
		writeError(w, badRequest("reason must be under 200 and details under 2000 characters"))
		return
	}

	page, err := s.store.GetPublicPage(r.Context(), username, slug)
	if err != nil && !errors.Is(err, store.ErrForbidden) {
		writeError(w, errNotFound("no such published page"))
		return
	}

	if err := s.store.InsertAbuseReport(r.Context(), page.ID, hashIP(r), req.Reason, req.Details); err != nil {
		writeError(w, err)
		return
	}
	log.Printf("abuse report filed for publish %s", page.ID)
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "received"})
}
