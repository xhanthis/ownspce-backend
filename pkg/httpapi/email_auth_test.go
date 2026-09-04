package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/ownspce/backend/pkg/store"
)

// The unauthenticated auth routes are rate limited per client IP, and every
// request httptest builds carries the same one. These tests deliberately spend
// a dozen sign-in attempts, so each gets its own address — otherwise the suite
// throttles itself and the failure looks like a product bug.
var testIP atomic.Uint32

// doFrom is h.do with a client address of its own.
func (h *harness) doFrom(method, path string, a *actor, body any) *httptest.ResponseRecorder {
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
	if a != nil {
		req.Header.Set("Authorization", "Bearer "+a.Token)
	}
	n := testIP.Add(1)
	req.Header.Set("X-Forwarded-For", fmt.Sprintf("198.51.100.%d", n%250+1))

	rec := httptest.NewRecorder()
	h.server.ServeHTTP(rec, req)
	return rec
}

// issueSignInCode mints a sign-in code the way the send endpoint does, and hands
// back the plaintext. Tests cannot read a code out of the database — only its
// SHA-256 is stored, which is the property worth having — so they mint through
// the store and post through HTTP.
func (h *harness) issueSignInCode(email string, userID *uuid.UUID) string {
	h.t.Helper()
	code, _, err := h.store.IssueEmailCode(context.Background(), email, store.EmailCodePurposeSignIn, userID, nil)
	if err != nil {
		h.t.Fatalf("issue sign-in code: %v", err)
	}
	return code
}

func (h *harness) issueDeviceCode(email string, userID, deviceID uuid.UUID) string {
	h.t.Helper()
	code, _, err := h.store.IssueEmailCode(context.Background(), email, store.EmailCodePurposeDevice, &userID, &deviceID)
	if err != nil {
		h.t.Fatalf("issue device code: %v", err)
	}
	return code
}

func sessionBody(email, code string, publicKey []byte) map[string]any {
	return map[string]any{
		"provider": "email",
		"email":    email,
		"code":     code,
		"device":   map[string]any{"label": "test browser", "platform": "web", "publicKey": encodeB64(publicKey)},
	}
}

func TestEmailCodeCreatesAnAccountAndSignsIn(t *testing.T) {
	// Arrange
	h := newHarness(t)
	email := fmt.Sprintf("email-%s@ownspce.test", uuid.NewString())
	code := h.issueSignInCode(email, nil)

	// Act
	rec := h.doFrom(http.MethodPost, "/v1/auth/session", nil, sessionBody(email, code, randomBytes(t, 32)))

	// Assert
	requireStatus(t, rec, http.StatusOK)
	body := decodeBody(t, rec)
	if body["isNewUser"] != true {
		t.Fatalf("expected a new account: %s", rec.Body.String())
	}
	user := body["user"].(map[string]any)
	if user["email"] != email {
		t.Fatalf("email = %v, want %s", user["email"], email)
	}
	h.users = append(h.users, uuid.MustParse(user["id"].(string)))

	// The first device of a brand new account is trusted, as with any provider.
	if device := body["device"].(map[string]any); device["status"] != store.DeviceStatusActive {
		t.Fatalf("first device status = %v, want active", device["status"])
	}
}

// TestFirstSessionCarriesTheEscrowKey guards the moment the whole recovery story
// is decided. A client wraps its first household key to the escrow public key
// this response carries; an empty one produces a household that no email code
// can ever open, and nothing later would notice.
func TestFirstSessionCarriesTheEscrowKey(t *testing.T) {
	// Arrange
	h := newHarness(t)
	email := fmt.Sprintf("escrow-%s@ownspce.test", uuid.NewString())
	code := h.issueSignInCode(email, nil)

	// Act
	rec := h.doFrom(http.MethodPost, "/v1/auth/session", nil, sessionBody(email, code, randomBytes(t, 32)))

	// Assert
	requireStatus(t, rec, http.StatusOK)
	body := decodeBody(t, rec)
	user := body["user"].(map[string]any)
	h.users = append(h.users, uuid.MustParse(user["id"].(string)))

	escrow, _ := user["recoveryPublicKey"].(string)
	if escrow == "" {
		t.Fatal("the very first session carried no escrow key, so a household created now could never be recovered")
	}
	if got := decodeKey(t, escrow); len(got) != 32 {
		t.Fatalf("escrow public key is %d bytes, want 32", len(got))
	}
}

func TestEmailCodeSignsIntoTheSameAccountAsGoogle(t *testing.T) {
	// Arrange — an account that already exists because somebody used Google.
	h := newHarness(t)
	existing := h.signUp("google user")
	user, err := h.store.GetUser(context.Background(), existing.UserID)
	if err != nil {
		t.Fatalf("load user: %v", err)
	}
	code := h.issueSignInCode(user.Email, &user.ID)

	// Act
	rec := h.doFrom(http.MethodPost, "/v1/auth/session", nil, sessionBody(user.Email, code, randomBytes(t, 32)))

	// Assert — one account, not two.
	requireStatus(t, rec, http.StatusOK)
	body := decodeBody(t, rec)
	if body["isNewUser"] != false {
		t.Fatalf("email sign-in created a second account for %s", user.Email)
	}
	if body["user"].(map[string]any)["id"] != user.ID.String() {
		t.Fatalf("signed into %v, want %s", body["user"].(map[string]any)["id"], user.ID)
	}
	// A second device on an existing account still has to be let in.
	if device := body["device"].(map[string]any); device["status"] != store.DeviceStatusPending {
		t.Fatalf("second device status = %v, want pending", device["status"])
	}
}

func TestEmailCodeIsSingleUse(t *testing.T) {
	// Arrange
	h := newHarness(t)
	existing := h.signUp("replay")
	user, err := h.store.GetUser(context.Background(), existing.UserID)
	if err != nil {
		t.Fatalf("load user: %v", err)
	}
	code := h.issueSignInCode(user.Email, &user.ID)
	requireStatus(t, h.doFrom(http.MethodPost, "/v1/auth/session", nil, sessionBody(user.Email, code, randomBytes(t, 32))), http.StatusOK)

	// Act — the same code, a second time.
	replay := h.doFrom(http.MethodPost, "/v1/auth/session", nil, sessionBody(user.Email, code, randomBytes(t, 32)))

	// Assert
	requireStatus(t, replay, http.StatusUnauthorized)
}

func TestWrongEmailCodeBurnsAfterFiveTries(t *testing.T) {
	// Arrange
	h := newHarness(t)
	existing := h.signUp("guesser")
	user, err := h.store.GetUser(context.Background(), existing.UserID)
	if err != nil {
		t.Fatalf("load user: %v", err)
	}
	code := h.issueSignInCode(user.Email, &user.ID)

	// Act — five wrong guesses.
	for i := 0; i < 5; i++ {
		rec := h.doFrom(http.MethodPost, "/v1/auth/session", nil, sessionBody(user.Email, "000000", randomBytes(t, 32)))
		requireStatus(t, rec, http.StatusUnauthorized)
	}

	// Assert — the real code no longer works either, and says why.
	rec := h.doFrom(http.MethodPost, "/v1/auth/session", nil, sessionBody(user.Email, code, randomBytes(t, 32)))
	requireStatus(t, rec, http.StatusForbidden)
	if got := errorCode(t, rec); got != "code_exhausted" {
		t.Fatalf("error code = %s, want code_exhausted", got)
	}
}

func TestEmailCodeSendRevealsNothingAboutTheAddress(t *testing.T) {
	// Arrange
	h := newHarness(t)
	known := h.signUp("known")
	user, err := h.store.GetUser(context.Background(), known.UserID)
	if err != nil {
		t.Fatalf("load user: %v", err)
	}
	unknown := fmt.Sprintf("nobody-%s@ownspce.test", uuid.NewString())

	// Act
	withAccount := h.doFrom(http.MethodPost, "/v1/auth/email/code", nil, map[string]any{"email": user.Email})
	withoutAccount := h.doFrom(http.MethodPost, "/v1/auth/email/code", nil, map[string]any{"email": unknown})

	// Assert — identical answers, so the endpoint is not a membership oracle.
	requireStatus(t, withAccount, http.StatusNoContent)
	requireStatus(t, withoutAccount, http.StatusNoContent)
	if withAccount.Body.String() != withoutAccount.Body.String() {
		t.Fatalf("bodies differ: %q vs %q", withAccount.Body.String(), withoutAccount.Body.String())
	}

	// And a shape that could never be an address is refused outright.
	requireStatus(t, h.doFrom(http.MethodPost, "/v1/auth/email/code", nil, map[string]any{"email": "not-an-address"}), http.StatusBadRequest)
}

func TestEmailVerificationActivatesAPendingDeviceWithoutKeys(t *testing.T) {
	// Arrange — an account whose second device is pending and whose household
	// has no escrow wrap, so there is nothing for the server to hand over.
	h := newHarness(t)
	first := h.signUp("first device")
	pending := h.addDevice(first.UserID, "second device")
	if pending.Status != store.DeviceStatusPending {
		t.Fatalf("second device status = %s, want pending", pending.Status)
	}
	user, err := h.store.GetUser(context.Background(), first.UserID)
	if err != nil {
		t.Fatalf("load user: %v", err)
	}
	code := h.issueDeviceCode(user.Email, first.UserID, pending.DeviceID)

	// Act
	rec := h.do(http.MethodPost, "/v1/devices/"+pending.DeviceID.String()+"/approve", pending, map[string]any{"emailCode": code})

	// Assert — in, labelled as in by email, and holding nothing.
	requireStatus(t, rec, http.StatusOK)
	body := decodeBody(t, rec)
	if body["status"] != store.DeviceStatusActive {
		t.Fatalf("status = %v, want active", body["status"])
	}
	if body["approvedVia"] != store.ApprovedViaEmail {
		t.Fatalf("approvedVia = %v, want email", body["approvedVia"])
	}

	var keys int
	if err := h.store.Pool().QueryRow(context.Background(), "SELECT count(*) FROM space_keys WHERE device_id = $1", pending.DeviceID).Scan(&keys); err != nil {
		t.Fatalf("count space keys: %v", err)
	}
	if keys != 0 {
		t.Fatalf("email activation invented %d space keys for a household with no escrow wrap", keys)
	}
}

func TestDeviceCodeCannotActivateADifferentDevice(t *testing.T) {
	// Arrange — two pending devices on one account.
	h := newHarness(t)
	first := h.signUp("first device")
	target := h.addDevice(first.UserID, "the one that asked")
	other := h.addDevice(first.UserID, "the one that did not")
	user, err := h.store.GetUser(context.Background(), first.UserID)
	if err != nil {
		t.Fatalf("load user: %v", err)
	}
	code := h.issueDeviceCode(user.Email, first.UserID, target.DeviceID)

	// Act — the other device tries to spend the code minted for the target.
	rec := h.do(http.MethodPost, "/v1/devices/"+other.DeviceID.String()+"/approve", other, map[string]any{"emailCode": code})

	// Assert
	requireStatus(t, rec, http.StatusUnauthorized)
	device, err := h.store.LiveDevice(context.Background(), other.DeviceID)
	if err != nil {
		t.Fatalf("reload device: %v", err)
	}
	if device.Status != store.DeviceStatusPending {
		t.Fatalf("status = %s, want it left pending", device.Status)
	}
}

func TestDeviceCodeRequestIsOnlyForTheDeviceAsking(t *testing.T) {
	// Arrange
	h := newHarness(t)
	first := h.signUp("first device")
	other := h.addDevice(first.UserID, "someone else's device")

	// Act — asking for a code on behalf of another device.
	rec := h.do(http.MethodPost, "/v1/devices/"+other.DeviceID.String()+"/verify-email/code", first, nil)

	// Assert
	requireStatus(t, rec, http.StatusBadRequest)
}

func TestExpiredEmailCodeIsRefused(t *testing.T) {
	// Arrange
	h := newHarness(t)
	existing := h.signUp("latecomer")
	user, err := h.store.GetUser(context.Background(), existing.UserID)
	if err != nil {
		t.Fatalf("load user: %v", err)
	}
	code := h.issueSignInCode(user.Email, &user.ID)
	if _, err := h.store.Pool().Exec(context.Background(), "UPDATE email_codes SET expires_at = now() - interval '1 minute' WHERE email = $1 AND consumed_at IS NULL", user.Email); err != nil {
		t.Fatalf("age the code: %v", err)
	}

	// Act
	rec := h.doFrom(http.MethodPost, "/v1/auth/session", nil, sessionBody(user.Email, code, randomBytes(t, 32)))

	// Assert
	requireStatus(t, rec, http.StatusUnauthorized)
}

func TestEmailCodeCannotBeMixedWithWrappedKeys(t *testing.T) {
	// Arrange
	h := newHarness(t)
	first := h.signUp("first device")
	pending := h.addDevice(first.UserID, "second device")
	user, err := h.store.GetUser(context.Background(), first.UserID)
	if err != nil {
		t.Fatalf("load user: %v", err)
	}
	code := h.issueDeviceCode(user.Email, first.UserID, pending.DeviceID)

	// Act — an email code smuggled in alongside wraps the device invented.
	rec := h.do(http.MethodPost, "/v1/devices/"+pending.DeviceID.String()+"/approve", pending, map[string]any{
		"emailCode": code,
		"wrappedKeys": []map[string]any{
			{"spaceId": uuid.NewString(), "keyEpoch": 1, "wrappedKey": wrappedKey(t)},
		},
	})

	// Assert
	requireStatus(t, rec, http.StatusBadRequest)
}
