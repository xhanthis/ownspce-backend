package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/ownspce/backend/pkg/store"
	"golang.org/x/crypto/nacl/box"
)

// The web app and Money live on different origins, so a browser signed in to one
// has no way to see the other's session — different storage, different device
// keypair, different everything. The only thing they share is the cookie on the
// parent domain, and these tests are the contract for it.

const (
	appOrigin   = "https://app.ownspce.com"
	moneyOrigin = "https://money.ownspce.com"
)

// fromSurface issues a request the way a browser on one of the OwnSpce surfaces
// would: an Origin the API trusts, and whatever cookies that browser is
// carrying.
func (h *harness) fromSurface(method, path, origin string, cookies []*http.Cookie, a *actor, body any) *httptest.ResponseRecorder {
	h.t.Helper()

	var reader *bytes.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			h.t.Fatalf("encode request: %v", err)
		}
		reader = bytes.NewReader(encoded)
	} else {
		reader = bytes.NewReader(nil)
	}

	req := httptest.NewRequest(method, path, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Origin", origin)
	if a != nil {
		req.Header.Set("Authorization", "Bearer "+a.Token)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	n := testIP.Add(1)
	req.Header.Set("X-Forwarded-For", fmt.Sprintf("198.51.100.%d", n%250+1))

	rec := httptest.NewRecorder()
	h.server.ServeHTTP(rec, req)
	return rec
}

// sessionCookie plucks the cross-surface cookie out of a response, failing the
// test if it is not there.
func sessionCookie(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range (&http.Response{Header: rec.Header()}).Cookies() {
		if c.Name == sessionCookieName {
			return c
		}
	}
	t.Fatal("response set no cross-surface session cookie")
	return nil
}

// signInFromSurface signs a brand new account in through the real handler, as a
// browser on one of the surfaces.
func (h *harness) signInFromSurface(t *testing.T, origin string) (*actor, string, *http.Cookie) {
	t.Helper()
	email := fmt.Sprintf("surface-%s@ownspce.test", uuid.NewString())
	code := h.issueSignInCode(email, nil)
	public, _ := deviceKeypair(t)

	rec := h.fromSurface(http.MethodPost, "/v1/auth/session", origin, nil, nil, sessionBody(email, code, public[:]))
	requireStatus(t, rec, http.StatusOK)

	body := decodeBody(t, rec)
	user := body["user"].(map[string]any)
	h.users = append(h.users, uuid.MustParse(user["id"].(string)))

	device := body["device"].(map[string]any)
	return &actor{
		UserID:    uuid.MustParse(user["id"].(string)),
		DeviceID:  uuid.MustParse(device["id"].(string)),
		PublicKey: public[:],
		Token:     body["accessToken"].(string),
		Status:    device["status"].(string),
	}, email, sessionCookie(t, rec)
}

// TestSignInSetsACookieOnlyABrowserCanUse pins the flags. Every one of them is
// load-bearing: without HttpOnly an XSS on any single surface lifts the session
// for all of them, without the parent Domain the sibling surface never receives
// it, and without Secure it travels in the clear.
func TestSignInSetsACookieOnlyABrowserCanUse(t *testing.T) {
	h := newHarness(t)

	_, _, cookie := h.signInFromSurface(t, appOrigin)

	if !cookie.HttpOnly {
		t.Error("the session cookie is readable by script")
	}
	if !cookie.Secure {
		t.Error("the session cookie is not marked Secure")
	}
	if cookie.Domain != h.server.cfg.SessionCookieDomain {
		t.Errorf("cookie domain = %q, want %q", cookie.Domain, h.server.cfg.SessionCookieDomain)
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("cookie SameSite = %v, want Lax", cookie.SameSite)
	}
	if cookie.MaxAge <= 0 {
		t.Errorf("cookie MaxAge = %d, want a positive lifetime", cookie.MaxAge)
	}
}

// TestTheOtherSurfaceContinuesWithoutASecondSignIn is the whole point of the
// cookie: somebody who signed in on the notes app and then opens Money is not
// asked to sign in again.
//
// The device the second surface registers is genuinely its own — separate
// origin, separate storage, separate keypair — which is why this cannot be done
// by simply sharing the first surface's tokens.
func TestTheOtherSurfaceContinuesWithoutASecondSignIn(t *testing.T) {
	// Arrange — signed in on the notes app.
	h := newHarness(t)
	first, _, cookie := h.signInFromSurface(t, appOrigin)

	// Act — Money opens with nothing but the cookie the browser is carrying.
	moneyPublic, _ := deviceKeypair(t)
	rec := h.fromSurface(http.MethodPost, "/v1/auth/continue", moneyOrigin, []*http.Cookie{cookie}, nil, map[string]any{
		"device": map[string]any{"label": "money browser", "platform": "web", "publicKey": encodeB64(moneyPublic[:])},
	})

	// Assert — same account, its own device, in and ready.
	requireStatus(t, rec, http.StatusOK)
	body := decodeBody(t, rec)
	if body["user"].(map[string]any)["id"] != first.UserID.String() {
		t.Fatalf("continued into %v, want %s", body["user"].(map[string]any)["id"], first.UserID)
	}
	device := body["device"].(map[string]any)
	if device["status"] != store.DeviceStatusActive {
		t.Fatalf("device status = %v, want active", device["status"])
	}
	if device["id"] == first.DeviceID.String() {
		t.Fatal("the second surface was handed the first surface's device rather than registering its own")
	}
	if body["accessToken"] == "" || body["refreshToken"] == "" {
		t.Fatal("continue returned no usable session")
	}

	// The cookie is rotated on the way through, so the copy just spent is not
	// the copy the browser now holds.
	rotated := sessionCookie(t, rec)
	if rotated.Value == cookie.Value {
		t.Error("continue did not rotate the session cookie")
	}

	// And the session it handed back really works.
	money := &actor{UserID: first.UserID, DeviceID: uuid.MustParse(device["id"].(string)), Token: body["accessToken"].(string)}
	requireStatus(t, h.do(http.MethodGet, "/v1/money/households", money, nil), http.StatusOK)
}

// TestContinueRefusesABrowserWithNoSession keeps the hop cheap and safe: a
// browser that has never signed in anywhere pays one 401 and then paints its
// own sign-in screen.
func TestContinueRefusesABrowserWithNoSession(t *testing.T) {
	h := newHarness(t)
	public, _ := deviceKeypair(t)
	body := map[string]any{"device": map[string]any{"label": "cold browser", "platform": "web", "publicKey": encodeB64(public[:])}}

	none := h.fromSurface(http.MethodPost, "/v1/auth/continue", moneyOrigin, nil, nil, body)
	forged := h.fromSurface(http.MethodPost, "/v1/auth/continue", moneyOrigin, []*http.Cookie{{Name: sessionCookieName, Value: "not-a-real-token"}}, nil, body)

	requireStatus(t, none, http.StatusUnauthorized)
	requireStatus(t, forged, http.StatusUnauthorized)

	// A cookie that cannot work is cleared rather than left to fail every cold
	// start for the rest of its lifetime.
	if cleared := sessionCookie(t, forged); cleared.Value != "" || cleared.MaxAge >= 0 {
		t.Errorf("a rejected cookie was left in place: value %q, MaxAge %d", cleared.Value, cleared.MaxAge)
	}
}

// TestSigningOutEndsTheSessionOnEverySurface is deliberate behaviour, not a side
// effect. Signing out of Money and staying silently signed in on the notes app
// is worse than signing out of both, so logout clears the cookie and revokes
// what it carried — the second half being what protects a copy taken earlier.
func TestSigningOutEndsTheSessionOnEverySurface(t *testing.T) {
	// Arrange
	h := newHarness(t)
	first, _, cookie := h.signInFromSurface(t, appOrigin)

	// Act
	out := h.fromSurface(http.MethodPost, "/v1/auth/logout", appOrigin, []*http.Cookie{cookie}, first, nil)
	requireStatus(t, out, http.StatusNoContent)

	// Assert — cleared in the browser, and dead on the server.
	if cleared := sessionCookie(t, out); cleared.Value != "" || cleared.MaxAge >= 0 {
		t.Errorf("logout left the cookie in place: value %q, MaxAge %d", cleared.Value, cleared.MaxAge)
	}

	public, _ := deviceKeypair(t)
	replay := h.fromSurface(http.MethodPost, "/v1/auth/continue", moneyOrigin, []*http.Cookie{cookie}, nil, map[string]any{
		"device": map[string]any{"label": "money browser", "platform": "web", "publicKey": encodeB64(public[:])},
	})
	requireStatus(t, replay, http.StatusUnauthorized)
}

// TestAnInstalledAppIsHandedNoCookie keeps the token table from filling with
// rows nobody will ever present. A phone sends no Origin and keeps no cookie
// jar, so minting one for it is pure waste.
func TestAnInstalledAppIsHandedNoCookie(t *testing.T) {
	h := newHarness(t)
	email := fmt.Sprintf("phone-%s@ownspce.test", uuid.NewString())
	code := h.issueSignInCode(email, nil)
	public, _ := deviceKeypair(t)

	rec := h.doFrom(http.MethodPost, "/v1/auth/session", nil, map[string]any{
		"provider": "email",
		"email":    email,
		"code":     code,
		"device":   map[string]any{"label": "a phone", "platform": "ios", "publicKey": encodeB64(public[:])},
	})
	requireStatus(t, rec, http.StatusOK)
	h.users = append(h.users, uuid.MustParse(decodeBody(t, rec)["user"].(map[string]any)["id"].(string)))

	for _, c := range (&http.Response{Header: rec.Header()}).Cookies() {
		if c.Name == sessionCookieName {
			t.Fatal("an installed app was handed a browser cookie")
		}
	}
}

// TestContinueGivesTheNewSurfaceTheHouseholdKey closes the loop. Getting a
// session on the second surface is worth nothing if the ledger there is still
// sealed, so the device registered by continue collects the account's escrow
// copies exactly as a fresh sign-in would.
func TestContinueGivesTheNewSurfaceTheHouseholdKey(t *testing.T) {
	// Arrange — a household created on the notes surface, with an escrow copy.
	h := newHarness(t)
	owner, _, cookie := h.signInFromSurface(t, appOrigin)
	escrowPublic := h.escrowPublicKey(t, owner.UserID)

	spaceKey := randomBytes(t, 32)
	var ownerDevicePublic [32]byte
	copy(ownerDevicePublic[:], owner.PublicKey)

	spaceID := uuid.NewString()
	requireStatus(t, h.do(http.MethodPost, "/v1/money/households", owner, map[string]any{
		"spaceId": spaceID,
		"wrappedKeys": []map[string]any{
			{"deviceId": owner.DeviceID.String(), "wrappedKey": encodeB64(sealTo(t, spaceKey, ownerDevicePublic))},
			{"wrappedKey": encodeB64(sealTo(t, spaceKey, escrowPublic))},
		},
		"ciphertext": sealed(t),
	}), http.StatusCreated)

	// Act — Money opens on the same browser.
	moneyPublic, moneyPrivate := deviceKeypair(t)
	rec := h.fromSurface(http.MethodPost, "/v1/auth/continue", moneyOrigin, []*http.Cookie{cookie}, nil, map[string]any{
		"device": map[string]any{"label": "money browser", "platform": "web", "publicKey": encodeB64(moneyPublic[:])},
	})
	requireStatus(t, rec, http.StatusOK)
	body := decodeBody(t, rec)
	money := &actor{UserID: owner.UserID, DeviceID: uuid.MustParse(body["device"].(map[string]any)["id"].(string)), Token: body["accessToken"].(string)}

	// Assert — the ledger opens, with the key the household was sealed with.
	list := h.do(http.MethodGet, "/v1/money/households", money, nil)
	requireStatus(t, list, http.StatusOK)
	households := decodeBody(t, list)["households"].([]any)
	if len(households) != 1 {
		t.Fatalf("got %d households, want 1", len(households))
	}
	wrapped, ok := households[0].(map[string]any)["wrappedKey"].(string)
	if !ok || wrapped == "" {
		t.Fatal("the continued surface was given no household key, so its ledger is sealed")
	}
	opened, ok := box.OpenAnonymous(nil, decodeKey(t, wrapped), &moneyPublic, &moneyPrivate)
	if !ok {
		t.Fatal("the continued surface could not open the key it was given")
	}
	if !bytes.Equal(opened, spaceKey) {
		t.Fatal("the continued surface opened a different key than the household was sealed with")
	}

	// The escrow copy itself never moved: it is still exactly one row.
	var escrowWraps int
	if err := h.store.Pool().QueryRow(context.Background(), "SELECT count(*) FROM space_keys WHERE space_id = $1 AND device_id IS NULL", spaceID).Scan(&escrowWraps); err != nil {
		t.Fatalf("count escrow wraps: %v", err)
	}
	if escrowWraps != 1 {
		t.Fatalf("escrow wraps = %d, want 1", escrowWraps)
	}
}
