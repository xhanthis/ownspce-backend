package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/ownspce/backend/pkg/auth"
	"github.com/ownspce/backend/pkg/seal"
	"github.com/ownspce/backend/pkg/store"
)

// providerEmail is the third sign-in door beside google and apple: a code this
// API mailed, rather than a token somebody else's identity provider issued.
const providerEmail = "email"

type deviceRegistration struct {
	Label     string `json:"label"`
	Platform  string `json:"platform"`
	PublicKey string `json:"publicKey"`
}

type sessionRequest struct {
	Provider string             `json:"provider"`
	IDToken  string             `json:"idToken"`
	Email    string             `json:"email"`
	Code     string             `json:"code"`
	Device   deviceRegistration `json:"device"`
}

type userPayload struct {
	ID              string  `json:"id"`
	Email           string  `json:"email"`
	Name            string  `json:"name"`
	Username        *string `json:"username"`
	AvatarURL       *string `json:"avatarUrl"`
	Plan            string  `json:"plan"`
	StreakCount     int     `json:"streakCount"`
	StreakUpdatedOn *string `json:"streakUpdatedOn"`
	Theme           string  `json:"theme"`
	Font            string  `json:"font"`
	Palette         string  `json:"palette"`
	// The theme the account built for itself, or null when it is on a preset.
	// The server stores and returns this shape without reading a colour out of
	// it — see sanitizeCustomTheme for what it is allowed to contain.
	CustomTheme json.RawMessage `json:"customTheme"`
	Language    string          `json:"language"`
	NotifyEmail bool            `json:"notifyEmail"`
	NotifyPush  bool            `json:"notifyPush"`
	// The wire name is historical. The key it carries used to be derived from a
	// 24-word phrase the person held; it is now an escrow key the server holds
	// for them. Clients still wrap household keys to it, so the field stays put
	// rather than breaking every other Ownspce surface for a rename.
	EscrowPublicKey string `json:"recoveryPublicKey"`
}

func toUserPayload(u *store.User) userPayload {
	var streakDate *string
	if u.StreakUpdatedOn != nil {
		formatted := u.StreakUpdatedOn.Format("2006-01-02")
		streakDate = &formatted
	}
	return userPayload{ID: u.ID.String(), Email: u.Email, Name: u.Name, Username: u.Username, AvatarURL: u.AvatarURL, Plan: u.Plan, StreakCount: u.StreakCount, StreakUpdatedOn: streakDate, Theme: u.Theme, Font: u.Font, Palette: u.Palette, CustomTheme: json.RawMessage(u.CustomTheme), Language: u.Language, NotifyEmail: u.NotifyEmail, NotifyPush: u.NotifyPush, EscrowPublicKey: encodeB64(u.EscrowPublicKey)}
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

// handleAuthSession exchanges a proven identity for an Ownspce session. Three
// providers reach here: google and apple hand over an OIDC id token, email hands
// over a code this API mailed. The device's X25519 public key is registered in
// the same call, because auth identity alone grants nothing readable — the
// device key is what will unwrap space keys later.
//
// Whichever door a person comes through, the address is the account. Somebody
// who signed up with Google and later types the same address lands on the row
// they already have, with the households already on it.
func (s *Server) handleAuthSession(w http.ResponseWriter, r *http.Request) {
	var req sessionRequest
	if err := decodeJSON(w, r, maxSmallBody, &req); err != nil {
		writeError(w, err)
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

	var (
		user  *store.User
		isNew bool
	)
	if req.Provider == providerEmail {
		user, isNew, err = s.userFromEmailCode(r.Context(), req.Email, req.Code)
	} else {
		user, isNew, err = s.userFromIDToken(r.Context(), req.Provider, req.IDToken)
	}
	if err != nil {
		writeError(w, err)
		return
	}

	// Minted here rather than at account creation so accounts made before escrow
	// existed pick one up on their next sign-in. The result is written back onto
	// the user being returned: a client wraps its first household key to what
	// this response carries, and an empty one would mean a household nobody can
	// ever recover.
	if escrowPublic := s.ensureEscrowKey(r.Context(), user.ID); len(escrowPublic) > 0 {
		user.EscrowPublicKey = escrowPublic
	}

	device, err := s.store.RegisterDevice(r.Context(), user.ID, req.Device.Label, req.Device.Platform, publicKey)
	if err != nil {
		writeError(w, err)
		return
	}

	device = s.admitDevice(r.Context(), user.ID, device)

	access, _, err := s.signer.Mint(user.ID, device.ID)
	if err != nil {
		writeError(w, err)
		return
	}
	refresh, err := s.store.IssueRefreshToken(r.Context(), user.ID, device.ID, device.Platform, nil)
	if err != nil {
		writeError(w, err)
		return
	}

	resp := sessionResponse{AccessToken: access, RefreshToken: refresh.Plaintext, ExpiresIn: int(auth.AccessTokenTTL.Seconds()), IsNewUser: isNew, User: toUserPayload(user)}
	resp.Device.ID = device.ID.String()
	resp.Device.Status = device.Status
	s.carrySession(w, r, user.ID, device.ID)
	writeJSON(w, http.StatusOK, resp)
}

type continueRequest struct {
	Device deviceRegistration `json:"device"`
}

// handleAuthContinue turns "this browser is signed in to OwnSpce somewhere" into
// a session on the surface asking.
//
// OwnSpce is one product on several addresses, and app.ownspce.com and
// money.ownspce.com are separate origins with separate storage — so each mints
// its own device keypair and neither can see the other's session. What they do
// share is the cookie on the parent domain, and this is the endpoint that spends
// it: it proves the account, registers the calling surface's device as a device
// of its own, admits it, and hands back exactly what every other door hands
// back.
//
// A surface tries this once before painting a sign-in screen. It costs one 401
// for a browser that has never signed in anywhere, which is the whole reason it
// is cheap enough to try on every cold start.
func (s *Server) handleAuthContinue(w http.ResponseWriter, r *http.Request) {
	var req continueRequest
	if err := decodeJSON(w, r, maxSmallBody, &req); err != nil {
		writeError(w, err)
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

	// Checked before the cookie is even read. This endpoint turns an ambient
	// credential into a device of the caller's choosing, holding every space key
	// the account has in escrow — so it answers only to the surfaces that are
	// meant to have it, never to the wider CORS allowlist that has to include
	// the origin serving published pages.
	if !s.cfg.SessionOriginAllowed(r.Header.Get("Origin")) {
		writeError(w, errForbidden("origin_not_permitted", "this origin cannot continue an OwnSpce session"))
		return
	}

	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		writeError(w, errUnauthorized("no OwnSpce session on this browser"))
		return
	}

	// Rotating is the validation. It checks the token is live, unspent and
	// belongs to a device nobody has revoked, and produces the successor this
	// response will put back in the cookie — so a stolen cookie is spent once
	// and then detectable, exactly like a stolen refresh token.
	rotated, err := s.store.RotateRefreshToken(r.Context(), cookie.Value)
	if err != nil {
		// Whatever went wrong, this browser is not getting in on this cookie
		// again. Clearing it stops every future cold start from paying for the
		// same failed hop.
		s.writeSessionCookie(w, "", time.Time{})
		writeError(w, errUnauthorized("this browser's OwnSpce session has expired"))
		return
	}

	user, err := s.store.GetUser(r.Context(), rotated.UserID)
	if err != nil {
		writeError(w, err)
		return
	}
	if escrowPublic := s.ensureEscrowKey(r.Context(), user.ID); len(escrowPublic) > 0 {
		user.EscrowPublicKey = escrowPublic
	}

	device, err := s.store.RegisterDevice(r.Context(), user.ID, req.Device.Label, req.Device.Platform, publicKey)
	if err != nil {
		writeError(w, err)
		return
	}
	device = s.admitDevice(r.Context(), user.ID, device)

	access, _, err := s.signer.Mint(user.ID, device.ID)
	if err != nil {
		writeError(w, err)
		return
	}
	refresh, err := s.store.IssueRefreshToken(r.Context(), user.ID, device.ID, device.Platform, nil)
	if err != nil {
		writeError(w, err)
		return
	}

	resp := sessionResponse{AccessToken: access, RefreshToken: refresh.Plaintext, ExpiresIn: int(auth.AccessTokenTTL.Seconds()), User: toUserPayload(user)}
	resp.Device.ID = device.ID.String()
	resp.Device.Status = device.Status
	s.writeSessionCookie(w, rotated.Token.Plaintext, rotated.Token.ExpiresAt)
	writeJSON(w, http.StatusOK, resp)
}

// admitDevice trusts a device and gives it the account's space keys.
//
// Signing in is the whole gate now. A device that has just proved the account —
// with Google, with a mailed code, or with an existing session on another
// OwnSpce surface — is active from that moment, and the escrow copy of every
// space key it should be able to read is re-wrapped for it here.
//
// It also finishes the job for devices left pending by the old approval flow.
// Those rows still exist, and their owners are sitting on a screen polling a
// status that nothing will ever change; the next sign-in on that device clears
// it.
//
// Only the spaces the device is missing are re-wrapped, space by space. A device
// that another device already handed one space to is not "done": it still
// collects every other space from escrow here. So an ordinary sign-in on a
// device that holds everything costs one query and never touches the escrow key.
//
// Safe to call on every request that should leave the device able to read what
// it is entitled to, not only at sign-in; the households list does exactly that.
// Args: ctx, userID, the device just registered or asking
// Returns: the device as it now stands, which is the caller's to send back
// Handles: escrow not configured and no escrow wraps — both leave the device
// active but keyless rather than failing the sign-in, because being signed in
// with nothing to read still beats not being signed in; and any failure along
// the way, which is logged and swallowed for the same reason
func (s *Server) admitDevice(ctx context.Context, userID uuid.UUID, device *store.Device) *store.Device {
	var keys []store.WrappedSpaceKey
	if s.escrow.Configured() {
		var err error
		keys, err = s.rewrapFromEscrow(ctx, userID, device.ID, device.PublicKey)
		if err != nil {
			log.Printf("escrow restore for %s: %v", device.ID, err)
			keys = nil
		}
	}

	// Nothing to do for an active device that already has what it needs.
	if device.Status == store.DeviceStatusActive && len(keys) == 0 {
		return device
	}

	admitted, err := s.store.ApproveDevice(ctx, userID, device.ID, nil, nil, keys)
	if err != nil {
		log.Printf("admit device %s: %v", device.ID, err)
		return device
	}
	return admitted
}

// userFromIDToken resolves a Google or Apple credential to an account.
// Args: ctx, provider, the id token as the provider issued it
// Returns: the user, whether this was their first sign-in, or an apiError
// Handles: a provider this deployment has no audience configured for, which is
// unavailable rather than unauthorized — the person did nothing wrong
func (s *Server) userFromIDToken(ctx context.Context, provider, idToken string) (*store.User, bool, error) {
	if idToken == "" {
		return nil, false, badRequest("idToken is required")
	}

	identity, err := s.verifier.Verify(ctx, provider, idToken)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrUnsupportedProvider):
			return nil, false, badRequest("provider must be google, apple or email")
		case errors.Is(err, auth.ErrNoAudienceConfigured):
			return nil, false, errUnavailable("this sign-in provider is not configured")
		case errors.Is(err, auth.ErrEmailUnverified):
			return nil, false, errForbidden("email_unverified", "the provider has not verified this email address")
		default:
			return nil, false, errUnauthorized("id token could not be verified")
		}
	}
	return s.store.UpsertUserByProvider(ctx, identity.Provider, identity.Subject, identity.Email, identity.Name, identity.AvatarURL)
}

// userFromEmailCode resolves a mailed code to an account, creating one the first
// time an address is proven.
//
// The code is the whole proof. It was mailed to this address, it is single-use,
// it expires in minutes, and five wrong guesses burn it — which is what makes a
// six-digit number acceptable here at all.
// Args: ctx, email as typed, code as typed
// Returns: the user, whether the account was just created, or an apiError
// Handles: a wrong, stale or already-spent code (401 with one message for all
// three, so a caller cannot use the difference to probe which addresses have
// codes outstanding), and a burnt code, which asks for a fresh one
func (s *Server) userFromEmailCode(ctx context.Context, email, code string) (*store.User, bool, error) {
	if !validEmail(email) {
		return nil, false, badRequest("email is required")
	}
	if code == "" {
		return nil, false, badRequest("code is required")
	}

	if _, err := s.store.ConsumeEmailCode(ctx, email, store.EmailCodePurposeSignIn, code, nil); err != nil {
		switch {
		case errors.Is(err, store.ErrCodeThrottled):
			return nil, false, errForbidden("code_exhausted", "too many wrong codes; ask for a new one")
		case errors.Is(err, store.ErrCodeInvalid):
			return nil, false, errUnauthorized("that code is wrong or has expired; ask for a new one")
		default:
			return nil, false, err
		}
	}
	return s.store.UpsertUserByEmail(ctx, email)
}

type emailCodeRequest struct {
	Email string `json:"email"`
}

// handleEmailCode mails a sign-in code, and says nothing about what it found.
//
// The response is 204 whether the address has an account, has none, or is being
// hammered — an endpoint that answered differently would be a free membership
// oracle for every address somebody cares to type. The one thing that does fail
// loudly is having no way to send mail at all, because telling somebody to check
// an inbox that will stay empty is worse than telling them it is broken.
func (s *Server) handleEmailCode(w http.ResponseWriter, r *http.Request) {
	var req emailCodeRequest
	if err := decodeJSON(w, r, maxSmallBody, &req); err != nil {
		writeError(w, err)
		return
	}
	if !validEmail(req.Email) {
		writeError(w, badRequest("email is required"))
		return
	}
	if !s.mailer.Configured() {
		writeError(w, errUnavailable("email sign-in is not configured on this deployment"))
		return
	}

	email := store.NormalizeEmail(req.Email)
	var userID *uuid.UUID
	if user, err := s.store.UserByEmail(r.Context(), email); err == nil {
		userID = &user.ID
	} else if !errors.Is(err, store.ErrNotFound) {
		writeError(w, err)
		return
	}

	code, _, err := s.store.IssueEmailCode(r.Context(), email, store.EmailCodePurposeSignIn, userID, nil)
	if err != nil {
		if errors.Is(err, store.ErrCodeThrottled) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeError(w, err)
		return
	}

	if err := s.mailer.SendSignInCode(r.Context(), email, code, store.EmailCodeTTL()); err != nil {
		log.Printf("send sign-in code: %v", err)
		writeError(w, errUnavailable("could not send the code; try again shortly"))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type refreshRequest struct {
	RefreshToken string `json:"refreshToken"`
}

// handleAuthRefresh rotates a refresh token. Replaying a spent token revokes the
// whole family, which turns a stolen refresh token into a detectable, self-limiting
// incident rather than durable access.
//
// It is also where a device stranded by the old approval flow is let in, and
// where the cross-surface cookie is kept alive.
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
	// A device left pending by the old approval flow holds a live refresh token
	// and never passes through sign-in again, so without this it would sit on
	// 403 device_pending forever while its owner refreshed happily every
	// quarter hour. Costs nothing for the active devices that are now every
	// other device.
	if device.Status != store.DeviceStatusActive {
		device = s.admitDevice(r.Context(), rotated.UserID, device)
	}

	access, _, err := s.signer.Mint(rotated.UserID, rotated.DeviceID)
	if err != nil {
		writeError(w, err)
		return
	}

	resp := sessionResponse{AccessToken: access, RefreshToken: rotated.Token.Plaintext, ExpiresIn: int(auth.AccessTokenTTL.Seconds()), User: toUserPayload(user)}
	resp.Device.ID = device.ID.String()
	resp.Device.Status = device.Status
	// A session kept alive here is a session kept alive everywhere. Without
	// this the cookie would age out on its own clock while the surface that set
	// it stayed signed in, and the sibling surfaces would start asking for a
	// login the person had never actually lost.
	s.carrySession(w, r, rotated.UserID, rotated.DeviceID)
	writeJSON(w, http.StatusOK, resp)
}

// handleAuthLogout revokes the calling device's refresh tokens and the
// cross-surface cookie. The access token lives out its remaining minutes; the
// client also discards its local keys.
func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	if err := s.store.RevokeDeviceTokens(r.Context(), callerFrom(r.Context()).DeviceID); err != nil {
		writeError(w, err)
		return
	}
	// Deliberately cross-surface: signing out of Money and staying silently
	// signed in on app is worse than signing out of both.
	s.dropSession(w, r)
	w.WriteHeader(http.StatusNoContent)
}
