package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"golang.org/x/crypto/nacl/box"
)

// continueOn calls POST /auth/continue the way a sibling surface does: no bearer
// token, a cookie the browser attached, and a device key of its own.
func (h *harness) continueOn(cookie string, publicKey []byte) *httptest.ResponseRecorder {
	h.t.Helper()
	body, err := json.Marshal(map[string]any{
		"device": map[string]any{"label": "money.ownspce.com", "platform": "web", "publicKey": encodeB64(publicKey)},
	})
	if err != nil {
		h.t.Fatalf("encode: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/continue", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: ContinuationCookie, Value: cookie})
	}
	rec := httptest.NewRecorder()
	h.server.ServeHTTP(rec, req)
	return rec
}

// cookieFrom pulls the continuation cookie out of a response, which is how a
// browser would have got it.
func cookieFrom(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == ContinuationCookie {
			return c.Value
		}
	}
	return ""
}

// TestSigningInHandsTheBrowserAProofForTheOtherSurfaces is the precondition for
// everything else here: without the cookie on the sign-in response, no sibling
// surface can do anything silently.
func TestSigningInHandsTheBrowserAProofForTheOtherSurfaces(t *testing.T) {
	// Arrange
	h := newHarness(t)
	email := fmt.Sprintf("continue-%s@ownspce.test", uuid.NewString())
	code := h.issueSignInCode(email, nil)

	// Act
	rec := h.doFrom(http.MethodPost, "/v1/auth/session", nil, sessionBody(email, code, randomBytes(t, 32)))

	// Assert
	requireStatus(t, rec, http.StatusOK)
	h.users = append(h.users, uuid.MustParse(decodeBody(t, rec)["user"].(map[string]any)["id"].(string)))

	if cookieFrom(t, rec) == "" {
		t.Fatal("signing in set no continuation cookie, so a sibling surface has nothing to present")
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name != ContinuationCookie {
			continue
		}
		if !c.HttpOnly {
			t.Error("the continuation cookie is readable by script on every subdomain")
		}
		if c.SameSite != http.SameSiteLaxMode {
			t.Errorf("SameSite = %v, want Lax", c.SameSite)
		}
	}
}

// TestASiblingSurfaceOpensWithoutASecondSignIn is the whole feature: money
// opening on a browser already signed in to the notes app, with its own device
// key, no sign-in screen, and the household keys already in hand.
func TestASiblingSurfaceOpensWithoutASecondSignIn(t *testing.T) {
	// Arrange — somebody signed in on one surface, with a household whose key is
	// wrapped for their device and for the account escrow key.
	h := newHarness(t)
	owner := h.signUp("app.ownspce.com")
	escrowPublic := h.escrowPublicKey(t, owner.UserID)

	spaceKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, spaceKey); err != nil {
		t.Fatalf("random space key: %v", err)
	}
	var ownerDevicePublic [32]byte
	copy(ownerDevicePublic[:], owner.PublicKey)

	requireStatus(t, h.do(http.MethodPost, "/v1/money/households", owner, map[string]any{
		"spaceId": uuid.NewString(),
		"wrappedKeys": []map[string]any{
			{"deviceId": owner.DeviceID.String(), "wrappedKey": encodeB64(sealTo(t, spaceKey, ownerDevicePublic))},
			{"wrappedKey": encodeB64(sealTo(t, spaceKey, escrowPublic))},
		},
		"ciphertext": sealed(h.t),
	}), http.StatusCreated)

	token, _, err := h.server.signer.MintContinuation(owner.UserID, owner.DeviceID)
	if err != nil {
		t.Fatalf("mint continuation: %v", err)
	}

	// Act — the second surface, with a device key of its own.
	moneyPublic, moneyPrivate := deviceKeypair(t)
	rec := h.continueOn(token, moneyPublic[:])

	// Assert — a session, an active device, and a key it can actually open.
	requireStatus(t, rec, http.StatusOK)
	body := decodeBody(t, rec)
	if device := body["device"].(map[string]any); device["status"] != "active" {
		t.Fatalf("device status = %v, want active — a sibling surface must not land on an approval screen", device["status"])
	}
	if body["user"].(map[string]any)["id"] != owner.UserID.String() {
		t.Fatal("continued into the wrong account")
	}

	money := &actor{UserID: owner.UserID, Token: body["accessToken"].(string), PublicKey: moneyPublic[:]}
	list := h.do(http.MethodGet, "/v1/money/households", money, nil)
	requireStatus(t, list, http.StatusOK)

	households := decodeBody(t, list)["households"].([]any)
	if len(households) != 1 {
		t.Fatalf("got %d households, want 1", len(households))
	}
	wrapped, _ := households[0].(map[string]any)["wrappedKey"].(string)
	if wrapped == "" {
		t.Fatal("the sibling surface was let in but given no household key")
	}
	opened, ok := box.OpenAnonymous(nil, decodeKey(t, wrapped), &moneyPublic, &moneyPrivate)
	if !ok || !bytes.Equal(opened, spaceKey) {
		t.Fatal("the key the sibling surface was given does not open the household")
	}

	// It is its own device, not a copy of the first.
	if body["device"].(map[string]any)["id"] == owner.DeviceID.String() {
		t.Fatal("the sibling surface reused the first device rather than registering its own")
	}
}

func TestContinuingWithoutACookieIsRefused(t *testing.T) {
	// Arrange
	h := newHarness(t)
	public, _ := deviceKeypair(t)

	// Act
	rec := h.continueOn("", public[:])

	// Assert
	requireStatus(t, rec, http.StatusUnauthorized)
}

// TestAnAccessTokenIsNotAContinuationToken keeps the two powers apart. An access
// token sits in client memory and is handled loosely; this cookie can register a
// device and collect escrow keys, so one must never be spendable as the other.
func TestAnAccessTokenIsNotAContinuationToken(t *testing.T) {
	// Arrange
	h := newHarness(t)
	owner := h.signUp("owner")
	public, _ := deviceKeypair(t)

	// Act — the account's own valid access token, presented as the cookie.
	rec := h.continueOn(owner.Token, public[:])

	// Assert
	requireStatus(t, rec, http.StatusUnauthorized)
}

// TestSigningOutTheOriginDeviceKillsItsContinuations is the revocation story. A
// cookie outlives the tab it was minted in, so signing a laptop out has to take
// its vouching power with it.
func TestSigningOutTheOriginDeviceKillsItsContinuations(t *testing.T) {
	// Arrange
	h := newHarness(t)
	owner := h.signUp("the laptop")
	token, _, err := h.server.signer.MintContinuation(owner.UserID, owner.DeviceID)
	if err != nil {
		t.Fatalf("mint continuation: %v", err)
	}
	requireStatus(t, h.do(http.MethodDelete, "/v1/devices/"+owner.DeviceID.String(), owner, nil), http.StatusNoContent)

	// Act
	public, _ := deviceKeypair(t)
	rec := h.continueOn(token, public[:])

	// Assert — refused, and the dead cookie cleared so the browser stops asking.
	requireStatus(t, rec, http.StatusUnauthorized)
	for _, c := range rec.Result().Cookies() {
		if c.Name == ContinuationCookie && c.MaxAge >= 0 {
			t.Errorf("a worthless cookie was left in place: MaxAge = %d", c.MaxAge)
		}
	}
}

// TestAPendingOriginDeviceCannotVouch closes the obvious escalation: a device
// nobody has let in must not be able to let a second one in and collect keys.
func TestAPendingOriginDeviceCannotVouch(t *testing.T) {
	// Arrange
	h := newHarness(t)
	owner := h.signUp("owner")
	pending := h.addDevice(owner.UserID, "a browser nobody approved")
	if pending.Status != "pending" {
		t.Fatalf("status = %q, want pending", pending.Status)
	}
	token, _, err := h.server.signer.MintContinuation(owner.UserID, pending.DeviceID)
	if err != nil {
		t.Fatalf("mint continuation: %v", err)
	}

	// Act
	public, _ := deviceKeypair(t)
	rec := h.continueOn(token, public[:])

	// Assert
	requireStatus(t, rec, http.StatusUnauthorized)
}

// TestContinuingIsIdempotentForTheSameBrowser guards the ordinary case of a
// reload: the same device key must not pile up devices on the account.
func TestContinuingIsIdempotentForTheSameBrowser(t *testing.T) {
	// Arrange
	h := newHarness(t)
	owner := h.signUp("app.ownspce.com")
	token, _, err := h.server.signer.MintContinuation(owner.UserID, owner.DeviceID)
	if err != nil {
		t.Fatalf("mint continuation: %v", err)
	}
	public, _ := deviceKeypair(t)

	// Act
	first := h.continueOn(token, public[:])
	second := h.continueOn(token, public[:])

	// Assert
	requireStatus(t, first, http.StatusOK)
	requireStatus(t, second, http.StatusOK)
	if decodeBody(t, first)["device"].(map[string]any)["id"] != decodeBody(t, second)["device"].(map[string]any)["id"] {
		t.Fatal("a reload registered a second device for the same browser")
	}

	devices, err := h.store.ListDevices(context.Background(), owner.UserID)
	if err != nil {
		t.Fatalf("list devices: %v", err)
	}
	if len(devices) != 2 {
		t.Fatalf("account has %d devices, want 2 (the origin and the sibling surface)", len(devices))
	}
}
