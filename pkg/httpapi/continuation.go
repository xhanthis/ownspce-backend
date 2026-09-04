package httpapi

import (
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/ownspce/backend/pkg/auth"
	"github.com/ownspce/backend/pkg/seal"
	"github.com/ownspce/backend/pkg/store"
)

// ContinuationCookie is the browser's evidence that somebody is already signed
// in to OwnSpce somewhere on this domain.
//
// It is scoped to the registrable domain rather than one host, which is the
// whole point: app.ownspce.com and money.ownspce.com are two faces of one
// product, and being asked to sign in again crossing between them reads as two
// products. HttpOnly so no script on any subdomain can read it, Secure so it
// never crosses plaintext, and Lax because every sender is same-site — a genuine
// third-party page cannot make the browser attach it.
const ContinuationCookie = "ospc_continue"

// setContinuation writes the cookie after a successful sign-in or refresh.
//
// The Domain attribute is set only in production. On localhost there is no
// registrable domain to share and a Domain of "localhost" is rejected by
// browsers, so development gets a host-only cookie that still exercises the
// same code path.
func (s *Server) setContinuation(w http.ResponseWriter, token string, maxAge int) {
	cookie := &http.Cookie{
		Name:     ContinuationCookie,
		Value:    token,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   s.cfg.IsProduction(),
		SameSite: http.SameSiteLaxMode,
	}
	if domain := s.cookieDomain(); domain != "" {
		cookie.Domain = domain
	}
	http.SetCookie(w, cookie)
}

// cookieDomain derives the shared domain from the configured public site, so a
// deployment on a different domain does not need a second setting to keep in
// step with the first.
func (s *Server) cookieDomain() string {
	if !s.cfg.IsProduction() {
		return ""
	}
	host := strings.TrimPrefix(strings.TrimPrefix(s.cfg.PublicSiteOrigin, "https://"), "http://")
	if idx := strings.IndexByte(host, '/'); idx >= 0 {
		host = host[:idx]
	}
	if host == "" || strings.Contains(host, ":") {
		return ""
	}
	return "." + host
}

type continueRequest struct {
	Device deviceRegistration `json:"device"`
}

// handleAuthContinue turns "already signed in on another OwnSpce surface" into a
// session on this one, with no sign-in screen at all.
//
// The cookie names a user and the device that minted it. That device is re-read
// here, so a laptop signed out of OwnSpce can no longer vouch for anything — the
// revocation the product already has covers this too, rather than a second
// mechanism nobody would think to use.
//
// The calling surface registers its own device key: money.ownspce.com never
// receives app.ownspce.com's private key, and could not, since the server has
// never held one. What it gets instead is its own device, activated on the
// strength of the cookie, with the household keys re-wrapped for it from the
// account's escrow copy. That is the same claim the email-code path makes, and
// the same claim a sign-in makes, so it grants no power a person did not already
// have on the surface they came from.
func (s *Server) handleAuthContinue(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(ContinuationCookie)
	if err != nil || cookie.Value == "" {
		writeError(w, errUnauthorized("no OwnSpce session on this browser"))
		return
	}

	verified, err := s.signer.VerifyContinuation(cookie.Value)
	if err != nil {
		s.clearContinuation(w)
		writeError(w, errUnauthorized("that OwnSpce session is no longer valid; sign in again"))
		return
	}

	// The minting device is the anchor. If it is gone, so is everything it said.
	origin, err := s.store.LiveDevice(r.Context(), verified.DeviceID)
	if err != nil || origin.UserID != verified.UserID || origin.Status != store.DeviceStatusActive {
		s.clearContinuation(w)
		writeError(w, errUnauthorized("the device that signed you in has been signed out; sign in again"))
		return
	}

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

	user, err := s.store.GetUser(r.Context(), verified.UserID)
	if err != nil {
		writeError(w, err)
		return
	}

	device, err := s.store.RegisterDevice(r.Context(), user.ID, req.Device.Label, req.Device.Platform, publicKey)
	if err != nil {
		writeError(w, err)
		return
	}

	// A surface arriving this way is let in, not left pending. Being sent to an
	// approval screen after proving an existing session is the friction this
	// endpoint exists to remove.
	if device.Status != store.DeviceStatusActive {
		keys, err := s.rewrapFromEscrow(r.Context(), user.ID, device.PublicKey)
		if err != nil {
			writeError(w, err)
			return
		}
		// Recorded as a device approval, because that is what it is: the device
		// already signed in on this browser is the one vouching. It is filed
		// under approved_by_device like any other, with the honest difference
		// that no human compared a fingerprint — the browser's own cookie stood
		// in for that, which is the trade this endpoint exists to make.
		device, err = s.store.ApproveDevice(r.Context(), user.ID, device.ID, &origin.ID, store.ApprovedViaDevice, keys)
		if err != nil {
			writeError(w, err)
			return
		}
	} else {
		s.restoreFromEscrow(r.Context(), user.ID, device)
	}

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

	s.refreshContinuation(w, user.ID, device.ID)

	resp := sessionResponse{AccessToken: access, RefreshToken: refresh.Plaintext, ExpiresIn: int(auth.AccessTokenTTL.Seconds()), User: toUserPayload(user)}
	resp.Device.ID = device.ID.String()
	resp.Device.Status = device.Status
	writeJSON(w, http.StatusOK, resp)
}

// refreshContinuation re-issues the cookie so an active person's silent hop
// keeps working without them ever signing in again.
//
// A failure is swallowed on purpose: the sign-in it accompanies has already
// succeeded, and losing the silent hop is not worth failing a login over.
func (s *Server) refreshContinuation(w http.ResponseWriter, userID, deviceID uuid.UUID) {
	token, _, err := s.signer.MintContinuation(userID, deviceID)
	if err != nil {
		return
	}
	s.setContinuation(w, token, int(auth.ContinuationTTL.Seconds()))
}

// clearContinuation removes the cookie, on sign-out and whenever one is found to
// be worthless — a browser that keeps presenting a dead cookie gets a redundant
// round trip on every launch.
func (s *Server) clearContinuation(w http.ResponseWriter) {
	s.setContinuation(w, "", -1)
}
