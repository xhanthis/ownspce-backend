package httpapi

import (
	"errors"
	"net/http"

	"github.com/ownspce/backend/pkg/linkpreview"
)

type linkPreviewRequest struct {
	URL string `json:"url"`
}

// handleLinkPreview reads a web page on the caller's behalf and returns what it
// says about itself, so a pasted link can be drawn as a card.
//
// The address arrives in the body, never the query string, and is not logged,
// stored or counted anywhere: this handler is the only thing on the API that
// ever sees what a user is reading, and it forgets it the moment the response
// is written. Every failure is an apiError on purpose — writeError logs
// anything else, and a wrapped fetch error would carry the address with it.
func (s *Server) handleLinkPreview(w http.ResponseWriter, r *http.Request) {
	var req linkPreviewRequest
	if err := decodeJSON(w, r, maxSmallBody, &req); err != nil {
		writeError(w, err)
		return
	}

	preview, err := s.previews.Fetch(r.Context(), req.URL)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, preview)
	case errors.Is(err, linkpreview.ErrBadURL):
		writeError(w, badRequest("url must be a web address"))
	case errors.Is(err, linkpreview.ErrBlockedHost):
		writeError(w, apiError{status: http.StatusBadRequest, Code: "link_blocked", Message: "that address cannot be previewed"})
	default:
		writeError(w, apiError{status: http.StatusUnprocessableEntity, Code: "preview_unavailable", Message: "that page could not be read"})
	}
}
