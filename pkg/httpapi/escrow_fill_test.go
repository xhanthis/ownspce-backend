package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"golang.org/x/crypto/nacl/box"
)

// randomSpaceKey is a household key as a client would mint it.
func randomSpaceKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("random space key: %v", err)
	}
	return key
}

// createHouseholdWithEscrow creates a household sealed to the owner's device and
// to whichever escrow public key the test hands it, which is not always the one
// the account currently has.
func (h *harness) createHouseholdWithEscrow(owner *actor, spaceKey []byte, escrowPublic [32]byte) string {
	h.t.Helper()
	var ownerDevicePublic [32]byte
	copy(ownerDevicePublic[:], owner.PublicKey)

	spaceID := uuid.NewString()
	rec := h.do(http.MethodPost, "/v1/money/households", owner, map[string]any{
		"spaceId": spaceID,
		"wrappedKeys": []map[string]any{
			{"deviceId": owner.DeviceID.String(), "wrappedKey": encodeB64(sealTo(h.t, spaceKey, ownerDevicePublic))},
			{"wrappedKey": encodeB64(sealTo(h.t, spaceKey, escrowPublic))},
		},
		"ciphertext": sealed(h.t),
	})
	requireStatus(h.t, rec, http.StatusCreated)
	return spaceID
}

// householdKeyFor lists households as the actor and returns the wrapped key the
// server handed it for the one household, or "" when it was given none.
func (h *harness) householdKeyFor(a *actor) string {
	h.t.Helper()
	list := h.do(http.MethodGet, "/v1/money/households", a, nil)
	requireStatus(h.t, list, http.StatusOK)
	households := decodeBody(h.t, list)["households"].([]any)
	if len(households) != 1 {
		h.t.Fatalf("got %d households, want 1", len(households))
	}
	wrapped, _ := households[0].(map[string]any)["wrappedKey"].(string)
	return wrapped
}

// mustOpen proves a wrapped key is the household key sealed for this device,
// not merely bytes of the right shape.
func mustOpen(t *testing.T, wrapped string, public, private [32]byte, want []byte) {
	t.Helper()
	got, ok := box.OpenAnonymous(nil, decodeKey(t, wrapped), &public, &private)
	if !ok {
		t.Fatal("the device could not open the key it was given")
	}
	if !bytes.Equal(got, want) {
		t.Fatal("the device was given a different key than the household was sealed with")
	}
}

// TestListingHouseholdsFillsTheOneThisDeviceIsMissing is the production case
// verbatim: a browser let in and handed a workspace key by another device, and
// so holding one key, but not the household's. Sign-in used to try escrow only
// for a device holding nothing, so this browser sat on the waiting screen
// polling a list that could never change. Now the list itself fills the gap.
func TestListingHouseholdsFillsTheOneThisDeviceIsMissing(t *testing.T) {
	// Arrange — a household with an escrow copy, and a browser that another
	// device approved with a workspace key only.
	h := newHarness(t)
	owner := h.signUp("the phone")
	spaceKey := randomSpaceKey(t)
	h.createHouseholdWithEscrow(owner, spaceKey, h.escrowPublicKey(t, owner.UserID))

	workspace := h.createSpace(owner)
	browserPublic, browserPrivate := deviceKeypair(t)
	device, err := h.store.RegisterDevice(context.Background(), owner.UserID, "the browser", "web", browserPublic[:])
	if err != nil {
		t.Fatalf("register device: %v", err)
	}
	requireStatus(t, h.do(http.MethodPost, "/v1/devices/"+device.ID.String()+"/approve", owner, map[string]any{
		"wrappedKeys": []map[string]any{{"spaceId": workspace, "keyEpoch": 1, "wrappedKey": wrappedKey(t)}},
	}), http.StatusOK)

	token, _, err := h.server.signer.Mint(owner.UserID, device.ID)
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}
	browser := &actor{UserID: owner.UserID, DeviceID: device.ID, PublicKey: browserPublic[:], Token: token}

	// Act — the waiting screen's poll.
	wrapped := h.householdKeyFor(browser)

	// Assert — the browser can open the ledger, and the workspace key it already
	// held was left alone rather than counted as "this device has its keys".
	if wrapped == "" {
		t.Fatal("the browser was given no household key")
	}
	mustOpen(t, wrapped, browserPublic, browserPrivate, spaceKey)
}

// TestAStaleEscrowCopyIsReportedAsAGapAndRefiledInPlace covers the account
// that carried a client-generated recovery key before the server minted its
// own. The household was sealed to the old key; the mint replaced it; the copy
// on file opens under nothing the server holds. It has to be visible as a gap so
// a device still holding the key re-seals it, the re-seal has to replace the
// old row rather than bounce off it, and a fresh device has to get in from the
// new copy.
func TestAStaleEscrowCopyIsReportedAsAGapAndRefiledInPlace(t *testing.T) {
	// Arrange — an account whose recovery key its own client set, and a
	// household sealed to that key.
	h := newHarness(t)
	owner := h.signUp("the laptop that still holds the key")
	clientRecoveryPublic, _ := deviceKeypair(t)
	if _, err := h.store.Pool().Exec(context.Background(), "UPDATE users SET recovery_public_key = $2 WHERE id = $1", owner.UserID, clientRecoveryPublic[:]); err != nil {
		t.Fatalf("set client recovery key: %v", err)
	}
	spaceKey := randomSpaceKey(t)
	spaceID := h.createHouseholdWithEscrow(owner, spaceKey, clientRecoveryPublic)

	// The server mints the account's escrow key over the client's.
	escrowPublic := h.escrowPublicKey(t, owner.UserID)
	if bytes.Equal(escrowPublic[:], clientRecoveryPublic[:]) {
		t.Fatal("the server did not mint a new escrow key over the client's")
	}

	// Assert — the stale copy shows up as the account's recovery gap, carrying
	// the key it should now be sealed to.
	gaps := h.do(http.MethodGet, "/v1/money/households/"+spaceID+"/key-gaps", owner, nil)
	requireStatus(t, gaps, http.StatusOK)
	recovery := recoveryGaps(t, decodeBody(t, gaps))
	if len(recovery) != 1 {
		t.Fatalf("got %d recovery gaps, want 1: %s", len(recovery), gaps.Body.String())
	}
	if got := recovery[0]["publicKey"]; got != encodeB64(escrowPublic[:]) {
		t.Fatalf("recovery gap names key %v, want the account's current escrow key", got)
	}

	// A fresh browser signing in is let in but handed nothing: the only copy on
	// file cannot be opened, and a bogus key would be worse than none.
	user, err := h.store.GetUser(context.Background(), owner.UserID)
	if err != nil {
		t.Fatalf("load user: %v", err)
	}
	browserPublic, browserPrivate := deviceKeypair(t)
	session := h.doFrom(http.MethodPost, "/v1/auth/session", nil, sessionBody(user.Email, h.issueSignInCode(user.Email, &user.ID), browserPublic[:]))
	requireStatus(t, session, http.StatusOK)
	browser := &actor{UserID: owner.UserID, Token: decodeBody(t, session)["accessToken"].(string), PublicKey: browserPublic[:]}
	if wrapped := h.householdKeyFor(browser); wrapped != "" {
		t.Fatal("the browser was handed a key from a copy the server cannot open")
	}

	// Act — the laptop re-seals the household key to the new escrow key, the
	// way the family screen does for any gap.
	refile := h.do(http.MethodPost, "/v1/money/households/"+spaceID+"/keys", owner, map[string]any{
		"keyEpoch":    1,
		"wrappedKeys": []map[string]any{{"userId": owner.UserID.String(), "wrappedKey": encodeB64(sealTo(t, spaceKey, escrowPublic))}},
	})
	requireStatus(t, refile, http.StatusOK)
	if granted := decodeBody(t, refile)["granted"]; granted != float64(1) {
		t.Fatalf("granted = %v, want 1: the stale copy was not replaced", granted)
	}

	// Assert — the gap is gone, the browser gets in on its next poll, and
	// filing the same copy again changes nothing.
	gaps = h.do(http.MethodGet, "/v1/money/households/"+spaceID+"/key-gaps", owner, nil)
	requireStatus(t, gaps, http.StatusOK)
	if remaining := recoveryGaps(t, decodeBody(t, gaps)); len(remaining) != 0 {
		t.Fatalf("recovery gap still listed after re-filing: %s", gaps.Body.String())
	}

	wrapped := h.householdKeyFor(browser)
	if wrapped == "" {
		t.Fatal("the browser was given no household key after the copy was re-filed")
	}
	mustOpen(t, wrapped, browserPublic, browserPrivate, spaceKey)

	again := h.do(http.MethodPost, "/v1/money/households/"+spaceID+"/keys", owner, map[string]any{
		"keyEpoch":    1,
		"wrappedKeys": []map[string]any{{"userId": owner.UserID.String(), "wrappedKey": encodeB64(sealTo(t, spaceKey, escrowPublic))}},
	})
	requireStatus(t, again, http.StatusOK)
	if granted := decodeBody(t, again)["granted"]; granted != float64(0) {
		t.Fatalf("granted = %v on a repeat filing, want 0", granted)
	}
}

// recoveryGaps picks the account-escrow entries out of a key-gaps response,
// leaving the per-device ones a fresh browser legitimately produces.
func recoveryGaps(t *testing.T, body map[string]any) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, raw := range body["gaps"].([]any) {
		gap := raw.(map[string]any)
		if gap["recovery"] == true {
			out = append(out, gap)
		}
	}
	return out
}

// createSpaceSealedTo creates a notes space whose key is sealed to the owner's
// device and to the escrow public key the test hands it — a real seal, so the
// server's rewrap either opens it or does not.
func (h *harness) createSpaceSealedTo(owner *actor, spaceKey []byte, escrowPublic [32]byte) string {
	h.t.Helper()
	var ownerDevicePublic [32]byte
	copy(ownerDevicePublic[:], owner.PublicKey)

	rec := h.do(http.MethodPost, "/v1/spaces", owner, map[string]any{
		"wrappedKeys": []map[string]any{
			{"deviceId": owner.DeviceID.String(), "wrappedKey": encodeB64(sealTo(h.t, spaceKey, ownerDevicePublic))},
			{"wrappedKey": encodeB64(sealTo(h.t, spaceKey, escrowPublic))},
		},
	})
	requireStatus(h.t, rec, http.StatusCreated)
	return decodeBody(h.t, rec)["id"].(string)
}

// spaceKeyFor lists spaces as the actor and returns the wrapped key the server
// handed it for the named space, or "" when it was given none.
func (h *harness) spaceKeyFor(a *actor, spaceID string) string {
	h.t.Helper()
	list := h.do(http.MethodGet, "/v1/spaces", a, nil)
	requireStatus(h.t, list, http.StatusOK)
	for _, raw := range decodeBody(h.t, list)["spaces"].([]any) {
		space := raw.(map[string]any)
		if space["id"] == spaceID {
			wrapped, _ := space["wrappedKey"].(string)
			return wrapped
		}
	}
	h.t.Fatalf("space %s is not in the list", spaceID)
	return ""
}

// TestListingSpacesFillsTheOneThisDeviceIsMissing is the notes-side twin of the
// households test above. The notes client reads GET /spaces on every start and
// never re-signs in on its own, so a copy re-sealed by another device after
// this browser signed in has to reach it through the list — otherwise the
// browser would decide it had no space at all and mint a fresh one.
func TestListingSpacesFillsTheOneThisDeviceIsMissing(t *testing.T) {
	// Arrange — a space with an escrow copy, and a browser that another device
	// let in with a different space's key only.
	h := newHarness(t)
	owner := h.signUp("the laptop")
	spaceKey := randomSpaceKey(t)
	spaceID := h.createSpaceSealedTo(owner, spaceKey, h.escrowPublicKey(t, owner.UserID))

	other := h.createSpace(owner)
	browserPublic, browserPrivate := deviceKeypair(t)
	device, err := h.store.RegisterDevice(context.Background(), owner.UserID, "the browser", "web", browserPublic[:])
	if err != nil {
		t.Fatalf("register device: %v", err)
	}
	requireStatus(t, h.do(http.MethodPost, "/v1/devices/"+device.ID.String()+"/approve", owner, map[string]any{
		"wrappedKeys": []map[string]any{{"spaceId": other, "keyEpoch": 1, "wrappedKey": wrappedKey(t)}},
	}), http.StatusOK)

	token, _, err := h.server.signer.Mint(owner.UserID, device.ID)
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}
	browser := &actor{UserID: owner.UserID, DeviceID: device.ID, PublicKey: browserPublic[:], Token: token}

	// Act — the notes client's start-up list.
	wrapped := h.spaceKeyFor(browser, spaceID)

	// Assert — the browser can open the space it was never handed directly.
	if wrapped == "" {
		t.Fatal("the browser was given no key for the space it was missing")
	}
	mustOpen(t, wrapped, browserPublic, browserPrivate, spaceKey)
}

// escrowCurrentFor lists spaces as the actor and returns the escrowCurrent flag
// the server reported for the named space.
func (h *harness) escrowCurrentFor(a *actor, spaceID string) bool {
	h.t.Helper()
	list := h.do(http.MethodGet, "/v1/spaces", a, nil)
	requireStatus(h.t, list, http.StatusOK)
	for _, raw := range decodeBody(h.t, list)["spaces"].([]any) {
		space := raw.(map[string]any)
		if space["id"] == spaceID {
			current, _ := space["escrowCurrent"].(bool)
			return current
		}
	}
	h.t.Fatalf("space %s is not in the list", spaceID)
	return false
}

// TestAStaleEscrowCopyOfASpaceIsReportedRefiledAndThenDelivered is the notes-app
// twin of the household repair loop, and the production case behind "it started
// a new account when I logged in": a space sealed to the recovery key an account
// carried before the server minted its own. The copy on file opens under
// nothing, so a fresh browser is let in and handed no key. The list has to say
// so to a device that holds the key, that device's re-seal has to replace the
// dead row, and the fresh browser has to get in on its next list — with no
// approval step anywhere.
func TestAStaleEscrowCopyOfASpaceIsReportedRefiledAndThenDelivered(t *testing.T) {
	// Arrange — an account whose recovery key its own client set, and a space
	// sealed to that key.
	h := newHarness(t)
	owner := h.signUp("the laptop that still holds the key")
	clientRecoveryPublic, _ := deviceKeypair(t)
	if _, err := h.store.Pool().Exec(context.Background(), "UPDATE users SET recovery_public_key = $2 WHERE id = $1", owner.UserID, clientRecoveryPublic[:]); err != nil {
		t.Fatalf("set client recovery key: %v", err)
	}
	spaceKey := randomSpaceKey(t)
	spaceID := h.createSpaceSealedTo(owner, spaceKey, clientRecoveryPublic)

	// The server mints the account's escrow key over the client's.
	escrowPublic := h.escrowPublicKey(t, owner.UserID)
	if bytes.Equal(escrowPublic[:], clientRecoveryPublic[:]) {
		t.Fatal("the server did not mint a new escrow key over the client's")
	}

	// Assert — the holder is told the copy is not current, and a fresh browser
	// signing in is let in but handed nothing for this space.
	if h.escrowCurrentFor(owner, spaceID) {
		t.Fatal("a copy sealed to the retired key was reported as current")
	}
	user, err := h.store.GetUser(context.Background(), owner.UserID)
	if err != nil {
		t.Fatalf("load user: %v", err)
	}
	browserPublic, browserPrivate := deviceKeypair(t)
	session := h.doFrom(http.MethodPost, "/v1/auth/session", nil, sessionBody(user.Email, h.issueSignInCode(user.Email, &user.ID), browserPublic[:]))
	requireStatus(t, session, http.StatusOK)
	browser := &actor{UserID: owner.UserID, Token: decodeBody(t, session)["accessToken"].(string), PublicKey: browserPublic[:]}
	if wrapped := h.spaceKeyFor(browser, spaceID); wrapped != "" {
		t.Fatal("the browser was handed a key from a copy the server cannot open")
	}

	// Act — the laptop re-seals the space key to the new escrow key, the way
	// the notes client now does on its own the moment it opens the space.
	refile := h.do(http.MethodPost, "/v1/spaces/"+spaceID+"/escrow", owner, map[string]any{
		"keyEpoch":   1,
		"wrappedKey": encodeB64(sealTo(t, spaceKey, escrowPublic)),
	})
	requireStatus(t, refile, http.StatusOK)
	if granted := decodeBody(t, refile)["granted"]; granted != float64(1) {
		t.Fatalf("granted = %v, want 1: the stale copy was not replaced", granted)
	}

	// Assert — the copy is current, the browser gets in on its next list with
	// no approval, and filing the same copy again changes nothing.
	if !h.escrowCurrentFor(owner, spaceID) {
		t.Fatal("the re-sealed copy was not reported as current")
	}
	wrapped := h.spaceKeyFor(browser, spaceID)
	if wrapped == "" {
		t.Fatal("the browser was given no key after the copy was re-filed")
	}
	mustOpen(t, wrapped, browserPublic, browserPrivate, spaceKey)

	again := h.do(http.MethodPost, "/v1/spaces/"+spaceID+"/escrow", owner, map[string]any{
		"keyEpoch":   1,
		"wrappedKey": encodeB64(sealTo(t, spaceKey, escrowPublic)),
	})
	requireStatus(t, again, http.StatusOK)
	if granted := decodeBody(t, again)["granted"]; granted != float64(0) {
		t.Fatalf("granted = %v on a repeat filing, want 0", granted)
	}

	// A wrap sealed against an epoch the space is not on is refused rather than
	// filed as coverage nobody can use.
	stale := h.do(http.MethodPost, "/v1/spaces/"+spaceID+"/escrow", owner, map[string]any{
		"keyEpoch":   2,
		"wrappedKey": encodeB64(sealTo(t, spaceKey, escrowPublic)),
	})
	requireStatus(t, stale, http.StatusConflict)
}
