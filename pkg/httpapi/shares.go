package httpapi

import (
	"errors"
	"io"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/ownspce/backend/pkg/store"
)

// shareMagic is the first four bytes of the chunked container the client seals a
// share into ("OSA1"). Checking it rejects an obviously wrong body early; it is
// a sanity check on the format, never an attempt to read the content, which the
// server cannot decrypt.
var shareMagic = []byte{'O', 'S', 'A', '1'}

// handlePutShare stores the sealed snapshot behind a share link.
//
// The bytes travel through the API rather than object storage: a share is capped
// near a megabyte, which fits a request body, and keeping it here means the
// public read below needs no cross-origin storage configuration to work from any
// browser.
func (s *Server) handlePutShare(w http.ResponseWriter, r *http.Request) {
	spaceID, err := parseUUIDParam(chi.URLParam(r, "spaceID"), "spaceId")
	if err != nil {
		writeError(w, err)
		return
	}
	shareID, err := parseUUIDParam(chi.URLParam(r, "shareID"), "shareId")
	if err != nil {
		writeError(w, err)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxShareBody)
	sealed, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeError(w, errTooLarge("payload_too_large", "this page is too large to share"))
			return
		}
		writeError(w, err)
		return
	}
	if len(sealed) < len(shareMagic) || string(sealed[:len(shareMagic)]) != string(shareMagic) {
		writeError(w, badRequest("share body is not a sealed snapshot"))
		return
	}

	if err := s.store.UpsertShare(r.Context(), shareID, spaceID, sealed); err != nil {
		writeError(w, storeError(err, "no such share", "share_conflict", "that share could not be written", "share_forbidden", "that share id belongs to another space"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"shareId": shareID})
}

// handleDeleteShare revokes a link by destroying its ciphertext. A reader who
// already opened it keeps what they read; what revoking guarantees is that
// nobody can fetch it again.
func (s *Server) handleDeleteShare(w http.ResponseWriter, r *http.Request) {
	spaceID, err := parseUUIDParam(chi.URLParam(r, "spaceID"), "spaceId")
	if err != nil {
		writeError(w, err)
		return
	}
	shareID, err := parseUUIDParam(chi.URLParam(r, "shareID"), "shareId")
	if err != nil {
		writeError(w, err)
		return
	}

	if err := s.store.DeleteShare(r.Context(), shareID, spaceID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handlePublicShare serves a share's ciphertext to a reader who has only the
// link. Unauthenticated on purpose: they have no account, and what they receive
// is noise until the key in their URL fragment opens it — a fragment browsers
// never transmit, so this server cannot read what it just served.
//
// The response is deliberately uncacheable by shared caches and carries no hint
// of the originating space, and a missing row and a revoked one answer
// identically so the two cannot be told apart.
func (s *Server) handlePublicShare(w http.ResponseWriter, r *http.Request) {
	shareID, err := parseUUIDParam(chi.URLParam(r, "shareID"), "shareId")
	if err != nil {
		writeError(w, errNotFound("that link is no longer available"))
		return
	}

	ciphertext, err := s.store.GetShare(r.Context(), shareID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, errNotFound("that link is no longer available"))
			return
		}
		writeError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(ciphertext); err != nil {
		log.Printf("write share body: %v", err)
	}
}
