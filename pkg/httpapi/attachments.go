package httpapi

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/ownspce/backend/pkg/blob"
	"github.com/ownspce/backend/pkg/store"
)

// uploadGrantTTL bounds how long a signed upload URL stays usable. Long enough
// for a slow phone upload, short enough that a URL leaked from a log or a proxy
// is worthless by the time anyone finds it.
const uploadGrantTTL = 15 * time.Minute

// handleAttachmentUploadURL issues a signed, single-purpose URL for one upload.
//
// The bytes must not pass through a JSON request: a sealed photo runs to
// megabytes, well past what the serverless function fronting this API accepts as
// a body it has to parse. So the API authorizes the upload here — the space role
// is checked on this call — and hands back a URL that carries its own permission
// for exactly one space, one attachment id and one byte count.
func (s *Server) handleAttachmentUploadURL(w http.ResponseWriter, r *http.Request) {
	spaceID, attachmentID, err := attachmentParams(r)
	if err != nil {
		writeError(w, err)
		return
	}
	if !s.blob.Configured() {
		writeError(w, errUnavailable("object storage is not configured; attachments are unavailable"))
		return
	}

	var req struct {
		Size int64 `json:"size"`
	}
	if err := decodeJSON(w, r, 1<<10, &req); err != nil {
		writeError(w, err)
		return
	}
	if req.Size <= 0 || req.Size > maxAttachmentBody {
		writeError(w, errTooLarge("payload_too_large", fmt.Sprintf("an attachment may be at most %d bytes sealed", maxAttachmentBody)))
		return
	}

	signature, expiresAt := s.uploads.Sign(spaceID, attachmentID, req.Size, uploadGrantTTL)
	url := fmt.Sprintf("%s/v1/spaces/%s/attachments/%s/blob?size=%d&exp=%d&sig=%s", publicOrigin(r), spaceID, attachmentID, req.Size, expiresAt, signature)
	writeJSON(w, http.StatusOK, map[string]any{"url": url, "expiresIn": int(uploadGrantTTL.Seconds())})
}

// handleUploadAttachmentBlob accepts the sealed bytes at a signed URL and stores
// them in object storage.
//
// This route sits outside the authenticated group because the uploading fetch
// carries no session; the grant in the query string is the whole authorization,
// and it is verified against the body length actually received so a grant minted
// for a small file cannot be replayed to store a large one.
func (s *Server) handleUploadAttachmentBlob(w http.ResponseWriter, r *http.Request) {
	spaceID, attachmentID, err := attachmentParams(r)
	if err != nil {
		writeError(w, err)
		return
	}

	query := r.URL.Query()
	size, sizeErr := strconv.ParseInt(query.Get("size"), 10, 64)
	expiresAt, expErr := strconv.ParseInt(query.Get("exp"), 10, 64)
	if sizeErr != nil || expErr != nil {
		writeError(w, errForbidden("grant_invalid", "this upload link is not valid"))
		return
	}
	if err := s.uploads.Verify(spaceID, attachmentID, size, expiresAt, query.Get("sig")); err != nil {
		writeError(w, errForbidden("grant_invalid", "this upload link has expired or is not valid"))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, size)
	sealed, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, errTooLarge("payload_too_large", "the upload is larger than this link authorizes"))
		return
	}
	if int64(len(sealed)) != size {
		writeError(w, errForbidden("grant_invalid", "the upload does not match the size this link authorizes"))
		return
	}

	// Checked only once the request has been judged on its own merits: a forged
	// or oversized upload is refused whether or not storage happens to be up, so
	// an unauthenticated caller learns nothing about the service from it.
	if !s.blob.Configured() {
		writeError(w, errUnavailable("object storage is not configured; attachments are unavailable"))
		return
	}

	url, err := s.blob.Put(r.Context(), blob.RandomPath("attachments", ".bin"), "application/octet-stream", sealed, 0)
	if err != nil {
		writeError(w, err)
		return
	}
	superseded, err := s.store.CommitAttachment(r.Context(), attachmentID, spaceID, url, size)
	if err != nil {
		writeError(w, storeError(err, "no such attachment", "attachment_conflict", "that attachment could not be written", "attachment_forbidden", "that attachment id belongs to another space"))
		return
	}
	s.sweepBlob(superseded)
	writeJSON(w, http.StatusCreated, map[string]any{"size": len(sealed)})
}

// handleCommitAttachment confirms the row the upload already wrote.
//
// The row is created by the upload itself, immediately after the bytes land, so
// it can never point at an object that does not exist and no state has to
// survive between two requests that may reach different instances. This call
// stays in the contract because it is the client's checkpoint: it re-checks the
// space role and reports the size the server actually stored, and it answers
// 409 when the bytes were never uploaded.
func (s *Server) handleCommitAttachment(w http.ResponseWriter, r *http.Request) {
	spaceID, attachmentID, err := attachmentParams(r)
	if err != nil {
		writeError(w, err)
		return
	}

	var req struct {
		Size int64 `json:"size"`
	}
	if err := decodeJSON(w, r, 1<<10, &req); err != nil {
		writeError(w, err)
		return
	}

	attachment, err := s.store.GetAttachment(r.Context(), attachmentID, spaceID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, errConflict("upload_missing", "upload the attachment bytes before committing it"))
			return
		}
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"size": attachment.SizeBytes})
}

// handleGetAttachment streams one attachment's ciphertext back to a member of
// its space. The bytes are proxied rather than redirected so the object URL,
// which is unguessable but bearer-readable, never reaches the client.
func (s *Server) handleGetAttachment(w http.ResponseWriter, r *http.Request) {
	spaceID, attachmentID, err := attachmentParams(r)
	if err != nil {
		writeError(w, err)
		return
	}

	attachment, err := s.store.GetAttachment(r.Context(), attachmentID, spaceID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, errNotFound("no such attachment"))
			return
		}
		writeError(w, err)
		return
	}

	sealed, err := s.blob.Get(r.Context(), attachment.BlobURL, maxAttachmentBody)
	if err != nil {
		writeError(w, errNotFound("that attachment is no longer available"))
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(sealed); err != nil {
		log.Printf("write attachment body: %v", err)
	}
}

// handleDeleteAttachment removes the row and sweeps the object behind it.
func (s *Server) handleDeleteAttachment(w http.ResponseWriter, r *http.Request) {
	spaceID, attachmentID, err := attachmentParams(r)
	if err != nil {
		writeError(w, err)
		return
	}

	blobURL, err := s.store.DeleteAttachment(r.Context(), attachmentID, spaceID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeError(w, err)
		return
	}
	s.sweepBlob(blobURL)
	w.WriteHeader(http.StatusNoContent)
}

// attachmentParams reads the space and attachment ids shared by every route here.
func attachmentParams(r *http.Request) (uuid.UUID, uuid.UUID, error) {
	spaceID, err := parseUUIDParam(chi.URLParam(r, "spaceID"), "spaceId")
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	attachmentID, err := parseUUIDParam(chi.URLParam(r, "attachmentID"), "attachmentId")
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	return spaceID, attachmentID, nil
}

// sweepBlob deletes a superseded object in the background, since a failure to
// clean up must never fail the request that succeeded.
func (s *Server) sweepBlob(url string) {
	if url == "" {
		return
	}
	go func() {
		if err := s.blob.Delete(detachedContext(), []string{url}); err != nil {
			log.Printf("delete superseded attachment blob: %v", err)
		}
	}()
}

// publicOrigin reconstructs this API's externally reachable origin, which is
// what an upload URL has to be built from: behind Vercel the process only ever
// sees a proxied request, so the forwarded scheme is authoritative.
func publicOrigin(r *http.Request) string {
	scheme := "https"
	if forwarded := r.Header.Get("X-Forwarded-Proto"); forwarded != "" {
		scheme = forwarded
	} else if r.TLS == nil {
		scheme = "http"
	}
	return scheme + "://" + r.Host
}
