package httpapi

import (
	"errors"
	"net/http"

	"github.com/ownspce/backend/internal/auth"
	"github.com/ownspce/backend/internal/seal"
	"github.com/ownspce/backend/internal/store"
)

type deviceRegistration struct {
	Label     string `json:"label"`
	Platform  string `json:"platform"`
	PublicKey string `json:"publicKey"`
}

type sessionRequest struct {
	Provider string             `json:"provider"`
	IDToken  string             `json:"idToken"`
	Device   deviceRegistration `json:"device"`
}

type userPayload struct {
	ID                string  `json:"id"`
	Email             string  `json:"email"`
	Name              string  `json:"name"`
	Username          *string `json:"username"`
	AvatarURL         *string `json:"avatarUrl"`
	Plan              string  `json:"plan"`
	StreakCount       int     `json:"streakCount"`
	StreakUpdatedOn   *string `json:"streakUpdatedOn"`
	Theme             string  `json:"theme"`
	Language          string  `json:"language"`
	NotifyEmail       bool    `json:"notifyEmail"`
	NotifyPush        bool    `json:"notifyPush"`
	RecoveryPublicKey string  `json:"recoveryPublicKey"`
}

func toUserPayload(u *store.User) userPayload {
	var streakDate *string
	if u.StreakUpdatedOn != nil {
		formatted := u.StreakUpdatedOn.Format("2006-01-02")
		streakDate = &formatted
	}
	return userPayload{ID: u.ID.String(), Email: u.Email, Name: u.Name, Username: u.Username, AvatarURL: u.AvatarURL, Plan: u.Plan, StreakCount: u.StreakCount, StreakUpdatedOn: streakDate, Theme: u.Theme, Language: u.Language, NotifyEmail: u.NotifyEmail, NotifyPush: u.NotifyPush, RecoveryPublicKey: encodeB64(u.RecoveryPublicKey)}
}

type sessionResponse struct {
	AccessToken  string      `json:"accessToken"`
	RefreshToken string      `json:"refreshToken"`
	ExpiresIn    int         `json:"expiresIn"`
	IsNewUser    bool        `json:"isNewUser"`
	User         userPayload `json:"user"`
	Device       struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	} `json:"device"`
}

// handleAuthSession exchanges a Google or Apple ID token for an Ownspce session.
// The device's X25519 public key is registered in the same call, because auth
// identity alone grants nothing readable — the device key is what will unwrap
// space keys later.
func (s *Server) handleAuthSession(w http.ResponseWriter, r *http.Request) {
	var req sessionRequest
	if err := decodeJSON(w, r, maxSmallBody, &req); err != nil {
		writeError(w, err)
		return
	}
	if req.IDToken == "" {
		writeError(w, badRequest("idToken is required"))
		return
	}

	publicKey, err := decodeB64(req.Device.PublicKey, "device.publicKey")
	if err != nil {
		writeError(w, err)
		return
	}
	if err := seal.ValidatePublicKey(publicKey); err != nil {
		writeError(w, badRequest("%v", err))
		return
	}

	identity, err := s.verifier.Verify(r.Context(), req.Provider, req.IDToken)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrUnsupportedProvider):
			writeError(w, badRequest("provider must be google or apple"))
		case errors.Is(err, auth.ErrNoAudienceConfigured):
			writeError(w, errUnavailable("this sign-in provider is not configured"))
		case errors.Is(err, auth.ErrEmailUnverified):
			writeError(w, errForbidden("email_unverified", "the provider has not verified this email address"))
		default:
			writeError(w, errUnauthorized("id token could not be verified"))
		}
		return
	}

	user, isNew, err := s.store.UpsertUserByProvider(r.Context(), identity.Provider, identity.Subject, identity.Email, identity.Name, identity.AvatarURL)
	if err != nil {
		writeError(w, err)
		return
	}

	device, err := s.store.RegisterDevice(r.Context(), user.ID, req.Device.Label, req.Device.Platform, publicKey)
	if err != nil {
		writeError(w, err)
		return
	}

	access, _, err := s.signer.Mint(user.ID, device.ID)
	if err != nil {
		writeError(w, err)
		return
	}
	refresh, err := s.store.IssueRefreshToken(r.Context(), user.ID, device.ID, nil)
	if err != nil {
		writeError(w, err)
		return
	}

	resp := sessionResponse{AccessToken: access, RefreshToken: refresh.Plaintext, ExpiresIn: int(auth.AccessTokenTTL.Seconds()), IsNewUser: isNew, User: toUserPayload(user)}
	resp.Device.ID = device.ID.String()
	resp.Device.Status = device.Status
	writeJSON(w, http.StatusOK, resp)
}

type refreshRequest struct {
	RefreshToken string `json:"refreshToken"`
}

// handleAuthRefresh rotates a refresh token. Replaying a spent token revokes the
// whole family, which turns a stolen refresh token into a detectable, self-limiting
// incident rather than durable access.
func (s *Server) handleAuthRefresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := decodeJSON(w, r, maxSmallBody, &req); err != nil {
		writeError(w, err)
		return
	}
	if req.RefreshToken == "" {
		writeError(w, badRequest("refreshToken is required"))
		return
	}

	rotated, err := s.store.RotateRefreshToken(r.Context(), req.RefreshToken)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrTokenReuse):
			writeError(w, apiError{status: http.StatusUnauthorized, Code: "token_reused", Message: "this refresh token was already used; all sessions for the device have been revoked"})
		case errors.Is(err, store.ErrTokenExpired):
			writeError(w, apiError{status: http.StatusUnauthorized, Code: "token_expired", Message: "refresh token has expired, sign in again"})
		case errors.Is(err, store.ErrNotFound):
			writeError(w, errUnauthorized("refresh token is not recognised"))
		case errors.Is(err, store.ErrForbidden):
			writeError(w, errUnauthorized("device has been revoked"))
		default:
			writeError(w, err)
		}
		return
	}

	user, err := s.store.GetUser(r.Context(), rotated.UserID)
	if err != nil {
		writeError(w, err)
		return
	}
	device, err := s.store.LiveDevice(r.Context(), rotated.DeviceID)
	if err != nil {
		writeError(w, err)
		return
	}
	access, _, err := s.signer.Mint(rotated.UserID, rotated.DeviceID)
	if err != nil {
		writeError(w, err)
		return
	}

	resp := sessionResponse{AccessToken: access, RefreshToken: rotated.Token.Plaintext, ExpiresIn: int(auth.AccessTokenTTL.Seconds()), User: toUserPayload(user)}
	resp.Device.ID = device.ID.String()
	resp.Device.Status = device.Status
	writeJSON(w, http.StatusOK, resp)
}

// handleAuthLogout revokes the calling device's refresh tokens. The access token
// lives out its remaining minutes; the client also discards its local keys.
func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	if err := s.store.RevokeDeviceTokens(r.Context(), callerFrom(r.Context()).DeviceID); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
