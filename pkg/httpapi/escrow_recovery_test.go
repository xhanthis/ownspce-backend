package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// deviceKeypair mints a real X25519 keypair, so these tests exercise the actual
// sealed boxes rather than random bytes that merely have the right length.
func deviceKeypair(t *testing.T) (public, private [32]byte) {
	t.Helper()
	if _, err := io.ReadFull(rand.Reader, private[:]); err != nil {
		t.Fatalf("random key: %v", err)
	}
	pub, err := curve25519.X25519(private[:], curve25519.Basepoint)
	if err != nil {
		t.Fatalf("derive public key: %v", err)
	}
	copy(public[:], pub)
	return public, private
}

// decodeKey turns a base64 wrapped key from the API back into bytes.
func decodeKey(t *testing.T, raw string) []byte {
	t.Helper()
	b, err := decodeB64(raw, "wrappedKey")
	if err != nil {
		t.Fatalf("decode %q: %v", raw, err)
	}
	return b
}

func sealTo(t *testing.T, message []byte, recipient [32]byte) []byte {
	t.Helper()
	sealed, err := box.SealAnonymous(nil, message, &recipient, rand.Reader)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return sealed
}

// escrowPublicKey reads the account's escrow public key, minting one first the
// way a real sign-in does — the harness creates users through the store, which
// skips the sign-in handler.
func (h *harness) escrowPublicKey(t *testing.T, userID uuid.UUID) [32]byte {
	t.Helper()
	h.server.ensureEscrowKey(context.Background(), userID)

	public, sealedPrivate, err := h.store.EscrowKey(context.Background(), userID)
	if err != nil {
		t.Fatalf("read escrow key: %v", err)
	}
	if len(public) != 32 || len(sealedPrivate) == 0 {
		t.Fatalf("account has no escrow key: public %d bytes, private %d bytes", len(public), len(sealedPrivate))
	}

	var out [32]byte
	copy(out[:], public)
	return out
}

// TestLosingEveryDeviceAndRecoveringByEmail is the whole promise of escrow, end
// to end: a household is created, every device that could open it is gone, and a
// brand new browser proves the account's email address and gets a key it can
// actually decrypt with. If this passes and returns the original space key, a
// person who lost their phone gets their ledger back.
func TestLosingEveryDeviceAndRecoveringByEmail(t *testing.T) {
	// Arrange — a household whose key is wrapped for the owner's device and for
	// the account's escrow key, which is what a client does at creation.
	h := newHarness(t)
	owner := h.signUp("the phone that will be lost")
	escrowPublic := h.escrowPublicKey(t, owner.UserID)

	spaceKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, spaceKey); err != nil {
		t.Fatalf("random space key: %v", err)
	}

	var ownerDevicePublic [32]byte
	copy(ownerDevicePublic[:], owner.PublicKey)

	spaceID := uuid.NewString()
	create := h.do(http.MethodPost, "/v1/money/households", owner, map[string]any{
		"spaceId": spaceID,
		"wrappedKeys": []map[string]any{
			{"deviceId": owner.DeviceID.String(), "wrappedKey": encodeB64(sealTo(t, spaceKey, ownerDevicePublic))},
			{"wrappedKey": encodeB64(sealTo(t, spaceKey, escrowPublic))},
		},
		"ciphertext": sealed(h.t),
	})
	requireStatus(t, create, http.StatusCreated)

	// The phone is gone.
	requireStatus(t, h.do(http.MethodDelete, "/v1/devices/"+owner.DeviceID.String(), owner, nil), http.StatusNoContent)

	// A new browser signs in. It is the account's only live device, so it is
	// trusted the way any first device is — and the sign-in hands it the escrow
	// copies, which is what makes "sign in again and you are back" true.
	user, err := h.store.GetUser(context.Background(), owner.UserID)
	if err != nil {
		t.Fatalf("load user: %v", err)
	}
	newPublic, newPrivate := deviceKeypair(t)
	code := h.issueSignInCode(user.Email, &user.ID)

	session := h.doFrom(http.MethodPost, "/v1/auth/session", nil, sessionBody(user.Email, code, newPublic[:]))
	requireStatus(t, session, http.StatusOK)
	body := decodeBody(t, session)
	if device := body["device"].(map[string]any); device["status"] != "active" {
		t.Fatalf("replacement device status = %v, want active", device["status"])
	}
	replacement := &actor{UserID: owner.UserID, Token: body["accessToken"].(string), PublicKey: newPublic[:]}

	list := h.do(http.MethodGet, "/v1/money/households", replacement, nil)
	requireStatus(t, list, http.StatusOK)
	households := decodeBody(t, list)["households"].([]any)
	if len(households) != 1 {
		t.Fatalf("got %d households, want 1", len(households))
	}

	wrapped, ok := households[0].(map[string]any)["wrappedKey"].(string)
	if !ok || wrapped == "" {
		t.Fatal("the recovered device was given no household key")
	}
	recovered, ok := box.OpenAnonymous(nil, decodeKey(t, wrapped), &newPublic, &newPrivate)
	if !ok {
		t.Fatal("the recovered device could not open the key it was given")
	}
	if !bytes.Equal(recovered, spaceKey) {
		t.Fatalf("recovered a different key than the household was sealed with")
	}
}

// TestEscrowRecoverySkipsAHouseholdItCannotOpen proves the failure is partial
// rather than total: a household with no escrow wrap does not block the device
// from getting in, and does not produce a bogus key for itself either.
func TestEscrowRecoverySkipsAHouseholdItCannotOpen(t *testing.T) {
	// Arrange — one household with an escrow wrap, one without.
	h := newHarness(t)
	owner := h.signUp("owner")
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

	// The second household is created the old way: device wrap only.
	h.createHousehold(owner)

	newPublic, newPrivate := deviceKeypair(t)
	device, err := h.store.RegisterDevice(context.Background(), owner.UserID, "replacement", "web", newPublic[:])
	if err != nil {
		t.Fatalf("register device: %v", err)
	}
	token, _, err := h.server.signer.Mint(owner.UserID, device.ID)
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}
	replacement := &actor{UserID: owner.UserID, DeviceID: device.ID, PublicKey: newPublic[:], Token: token, Status: device.Status}

	user, err := h.store.GetUser(context.Background(), owner.UserID)
	if err != nil {
		t.Fatalf("load user: %v", err)
	}

	// Act
	code := h.issueDeviceCode(user.Email, owner.UserID, device.ID)
	requireStatus(t, h.do(http.MethodPost, "/v1/devices/"+device.ID.String()+"/approve", replacement, map[string]any{"emailCode": code}), http.StatusOK)

	// Assert — both households listed, exactly one openable.
	list := h.do(http.MethodGet, "/v1/money/households", replacement, nil)
	requireStatus(t, list, http.StatusOK)
	households := decodeBody(t, list)["households"].([]any)
	if len(households) != 2 {
		t.Fatalf("got %d households, want 2", len(households))
	}

	opened := 0
	for _, raw := range households {
		wrapped, _ := raw.(map[string]any)["wrappedKey"].(string)
		if wrapped == "" {
			continue
		}
		if recovered, ok := box.OpenAnonymous(nil, decodeKey(t, wrapped), &newPublic, &newPrivate); ok && bytes.Equal(recovered, spaceKey) {
			opened++
		}
	}
	if opened != 1 {
		t.Fatalf("opened %d households, want exactly the one with an escrow wrap", opened)
	}
}
