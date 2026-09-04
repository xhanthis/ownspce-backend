package httpapi

import (
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/ownspce/backend/pkg/store"
)

// sessionCookieName is the cross-surface session. OwnSpce is one product on
// several addresses, and this cookie is what makes signing in on one of them
// count on the others.
const sessionCookieName = "os_session"

// carrySession refreshes the cross-surface cookie for a caller who has just
// proved themselves.
//
// The cookie carries a refresh token in its own family, so it reuses every
// guarantee the device's own token already has — sliding expiry, replay
// detection, family revocation, an immediate death when the device is revoked —
// without a second credential type to reason about. Rotating rather than
// re-issuing keeps that family bounded; a rotation that cannot be honoured
// (expired, revoked, replayed long after the fact) simply starts a new one, so
// the cookie heals instead of going quietly stale.
//
// It authenticates an account, not a device. app.ownspce.com and
// money.ownspce.com are separate origins with separate storage, so each mints
// its own device keypair; the surface presenting this cookie is by definition
// not the device the token was issued to. That is the point, and it is why
// handleAuthContinue registers a device of its own rather than trusting the one
// named in the token.
//
// Args: w, r, userID, deviceID (the device that just authenticated)
// Handles: no cookie domain configured and a request that is not from a
// browser, both of which write nothing — a deployment whose surfaces do not
// share a registrable domain cannot use this, and a phone has no cookie jar to
// put it in; and any token failure, which is logged and dropped, because a
// missing cookie costs one extra sign-in while a failed response costs the
// session that was just earned
func (s *Server) carrySession(w http.ResponseWriter, r *http.Request, userID, deviceID uuid.UUID) {
	if !s.cookiesUsable(r) {
		return
	}

	if existing, err := r.Cookie(sessionCookieName); err == nil && existing.Value != "" {
		if rotated, err := s.store.RotateRefreshToken(r.Context(), existing.Value); err == nil {
			s.writeSessionCookie(w, rotated.Token.Plaintext, rotated.Token.ExpiresAt)
			return
		}
	}

	// Minted on the web window regardless of what the calling device is, because
	// the thing being written to is a browser cookie and it should not outlive
	// the browser session it stands for.
	issued, err := s.store.IssueRefreshToken(r.Context(), userID, deviceID, store.DevicePlatformWeb, nil)
	if err != nil {
		log.Printf("carry session for %s: %v", userID, err)
		return
	}
	s.writeSessionCookie(w, issued.Plaintext, issued.ExpiresAt)
}

// dropSession clears the cross-surface cookie and revokes what it carried.
//
// Both halves matter. Clearing it is what makes signing out of Money also sign
// out of app, rather than leaving somebody silently signed in on a surface they
// thought they had left. Revoking the family behind it is what makes that true
// for a copy of the cookie taken before the sign-out.
func (s *Server) dropSession(w http.ResponseWriter, r *http.Request) {
	if s.cfg.SessionCookieDomain == "" {
		return
	}

	if existing, err := r.Cookie(sessionCookieName); err == nil && existing.Value != "" {
		if err := s.store.RevokeTokenFamily(r.Context(), existing.Value); err != nil {
			log.Printf("revoke carried session: %v", err)
		}
	}
	s.writeSessionCookie(w, "", time.Time{})
}

// cookiesUsable reports whether this request can be answered with a
// cross-surface cookie at all: the deployment has a shared parent domain, and
// the caller is a browser on one of the designated app surfaces.
//
// The check is against SessionOrigins rather than the CORS allowlist, which is
// wider and necessarily includes the origin that serves published pages. An
// installed app sends no Origin and keeps no cookie jar, so it fails this too —
// minting one for it would file a token row nobody will ever present.
func (s *Server) cookiesUsable(r *http.Request) bool {
	if s.cfg.SessionCookieDomain == "" {
		return false
	}
	return s.cfg.SessionOriginAllowed(r.Header.Get("Origin"))
}

// writeSessionCookie sets or clears the cookie with the flags that make it safe
// to hand between surfaces.
//
// HttpOnly keeps it out of reach of any script on any surface, so an XSS on one
// of them cannot lift the session for all of them. SameSite=Lax is enough
// because api, app and money share a registrable domain and the request is
// therefore same-site, while still refusing the cookie to a genuinely foreign
// site. Secure is unconditional: this cookie is a credential and there is no
// deployment of it worth having over plain HTTP.
//
// Args: w, value, expiresAt (the token's own expiry; zero clears the cookie)
func (s *Server) writeSessionCookie(w http.ResponseWriter, value string, expiresAt time.Time) {
	maxAge := -1
	if !expiresAt.IsZero() {
		maxAge = int(time.Until(expiresAt).Seconds())
		if maxAge < 1 {
			maxAge = -1
			value = ""
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Domain:   s.cfg.SessionCookieDomain,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}
