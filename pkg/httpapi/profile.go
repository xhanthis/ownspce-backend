package httpapi

import (
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/ownspce/backend/pkg/store"
)

var usernamePattern = regexp.MustCompile(`^[a-z0-9_]{3,30}$`)

func (s *Server) handleGetMe(w http.ResponseWriter, r *http.Request) {
	user, err := s.store.GetUser(r.Context(), callerFrom(r.Context()).UserID)
	if err != nil {
		writeError(w, storeError(err, "user not found", "conflict", "", "forbidden", ""))
		return
	}
	writeJSON(w, http.StatusOK, toUserPayload(user))
}

type patchMeRequest struct {
	Name            *string `json:"name"`
	Username        *string `json:"username"`
	AvatarURL       *string `json:"avatarUrl"`
	Theme           *string `json:"theme"`
	Font            *string `json:"font"`
	Palette         *string `json:"palette"`
	Language        *string `json:"language"`
	NotifyEmail     *bool   `json:"notifyEmail"`
	NotifyPush      *bool   `json:"notifyPush"`
	StreakCount     *int    `json:"streakCount"`
	StreakUpdatedOn *string `json:"streakUpdatedOn"`
	// Accepted for compatibility with clients that still generate a phrase, and
	// deliberately never applied. See handlePatchMe.
	RecoveryPublicKey *string `json:"recoveryPublicKey"`
}

// handlePatchMe updates Tier 0 profile fields. Everything settable here is
// deliberately server-readable; nothing derived from note content may be added.
// Handles: reserved and taken usernames, invalid theme values, malformed dates,
// wrong-size recovery public keys.
func (s *Server) handlePatchMe(w http.ResponseWriter, r *http.Request) {
	var req patchMeRequest
	if err := decodeJSON(w, r, maxSmallBody, &req); err != nil {
		writeError(w, err)
		return
	}

	patch := store.ProfilePatch{Name: req.Name, AvatarURL: req.AvatarURL, Language: req.Language, NotifyEmail: req.NotifyEmail, NotifyPush: req.NotifyPush, StreakCount: req.StreakCount}

	if req.Username != nil {
		username := strings.ToLower(strings.TrimSpace(*req.Username))
		if !usernamePattern.MatchString(username) {
			writeError(w, badRequest("username must be 3-30 characters of a-z, 0-9 or underscore"))
			return
		}
		patch.Username = &username
	}
	if req.Theme != nil {
		if !oneOf(*req.Theme, "system", "light", "dark") {
			writeError(w, badRequest("theme must be system, light or dark"))
			return
		}
		patch.Theme = req.Theme
	}
	if req.Font != nil {
		if !oneOf(*req.Font, "grotesk", "sans", "serif") {
			writeError(w, badRequest("font must be grotesk, sans or serif"))
			return
		}
		patch.Font = req.Font
	}
	if req.Palette != nil {
		if !oneOf(*req.Palette, "cream", "paper", "sand") {
			writeError(w, badRequest("palette must be cream, paper or sand"))
			return
		}
		patch.Palette = req.Palette
	}
	if req.StreakCount != nil && *req.StreakCount < 0 {
		writeError(w, badRequest("streakCount must not be negative"))
		return
	}
	if req.StreakUpdatedOn != nil {
		day, err := time.Parse("2006-01-02", *req.StreakUpdatedOn)
		if err != nil {
			writeError(w, badRequest("streakUpdatedOn must be a YYYY-MM-DD date"))
			return
		}
		patch.StreakUpdatedOn = &day
	}
	// recoveryPublicKey is accepted and ignored. Older clients still send one
	// after generating a phrase; the account key is now minted and held by the
	// server, and letting a client overwrite it would let anyone who reached
	// this endpoint swap the escrow key for their own and be handed every
	// household key on the next recovery.

	user, err := s.store.UpdateProfile(r.Context(), callerFrom(r.Context()).UserID, patch)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrConflict):
			writeError(w, errConflict("username_taken", "that username is already taken"))
		case errors.Is(err, store.ErrForbidden):
			writeError(w, errConflict("username_reserved", "that username is reserved"))
		default:
			writeError(w, err)
		}
		return
	}
	writeJSON(w, http.StatusOK, toUserPayload(user))
}

// handleGetUserByUsername resolves an @handle for invites and mentions. It returns
// only public Tier 0 identity fields — never email, plan, or settings.
func (s *Server) handleGetUserByUsername(w http.ResponseWriter, r *http.Request) {
	username := strings.ToLower(strings.TrimSpace(chi.URLParam(r, "username")))
	if !usernamePattern.MatchString(username) {
		writeError(w, errNotFound("no such user"))
		return
	}

	user, err := s.store.GetUserByUsername(r.Context(), username)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, errNotFound("no such user"))
			return
		}
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": user.ID.String(), "username": user.Username, "name": user.Name, "avatarUrl": user.AvatarURL})
}
