package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/ownspce/backend/pkg/store"
)

var usernamePattern = regexp.MustCompile(`^[a-z0-9_]{3,30}$`)

// The presets a client may name, and the colour slots a theme built on one of
// them may override. Everything else in a palette — the soft accent tint, the
// tertiary text, the strong border, the drawer — is derived by the clients from
// these, so the list is short on purpose: a theme naming a slot that is not
// here was written by something this server does not understand.
var (
	themePalettes     = []string{"cream", "paper", "sand", "graphite", "midnight", "indigo", "evergreen"}
	customThemeSlots  = []string{"accent", "onAccent", "success", "warning", "danger", "background", "surface", "elevated", "border", "primaryText", "secondaryText"}
	themeColorPattern = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)
)

type customThemePayload struct {
	Base  string            `json:"base"`
	Light map[string]string `json:"light"`
	Dark  map[string]string `json:"dark"`
}

// sanitizeCustomTheme turns what a client sent into the exact JSON this server
// is willing to store, so nothing reaches the column that another client would
// have to defend itself against.
// Args: raw (the customTheme field as it arrived; JSON null clears the theme)
// Returns: the canonical JSON to store — nil to clear it — or a 400 error
// Handles: JSON null, an unknown base preset, an unknown colour slot, and a
// value that is not a six-digit hex colour
func sanitizeCustomTheme(raw json.RawMessage) ([]byte, error) {
	if string(raw) == "null" {
		return nil, nil
	}

	var theme customThemePayload
	if err := json.Unmarshal(raw, &theme); err != nil {
		return nil, badRequest("customTheme must be an object with base, light and dark")
	}
	if !oneOf(theme.Base, themePalettes...) {
		return nil, badRequest("customTheme.base must be one of %s", strings.Join(themePalettes, ", "))
	}

	for name, slots := range map[string]map[string]string{"light": theme.Light, "dark": theme.Dark} {
		for slot, value := range slots {
			if !oneOf(slot, customThemeSlots...) {
				return nil, badRequest("customTheme.%s may not set %s", name, slot)
			}
			if !themeColorPattern.MatchString(value) {
				return nil, badRequest("customTheme.%s.%s must be a #rrggbb colour", name, slot)
			}
		}
	}

	if theme.Light == nil {
		theme.Light = map[string]string{}
	}
	if theme.Dark == nil {
		theme.Dark = map[string]string{}
	}
	return json.Marshal(theme)
}

func (s *Server) handleGetMe(w http.ResponseWriter, r *http.Request) {
	user, err := s.store.GetUser(r.Context(), callerFrom(r.Context()).UserID)
	if err != nil {
		writeError(w, storeError(err, "user not found", "conflict", "", "forbidden", ""))
		return
	}
	writeJSON(w, http.StatusOK, toUserPayload(user))
}

type patchMeRequest struct {
	Name      *string `json:"name"`
	Username  *string `json:"username"`
	AvatarURL *string `json:"avatarUrl"`
	Theme     *string `json:"theme"`
	Font      *string `json:"font"`
	Palette   *string `json:"palette"`
	// A theme the account built for itself. Absent leaves the stored theme
	// alone; JSON null puts the account back on its preset.
	CustomTheme     json.RawMessage `json:"customTheme"`
	Language        *string         `json:"language"`
	NotifyEmail     *bool           `json:"notifyEmail"`
	NotifyPush      *bool           `json:"notifyPush"`
	StreakCount     *int            `json:"streakCount"`
	StreakUpdatedOn *string         `json:"streakUpdatedOn"`
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
		if !oneOf(*req.Palette, themePalettes...) {
			writeError(w, badRequest("palette must be one of %s", strings.Join(themePalettes, ", ")))
			return
		}
		patch.Palette = req.Palette
	}
	if req.CustomTheme != nil {
		theme, err := sanitizeCustomTheme(req.CustomTheme)
		if err != nil {
			writeError(w, err)
			return
		}
		patch.CustomTheme = &theme
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
