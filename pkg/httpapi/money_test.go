package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ownspce/backend/pkg/seal"
	"github.com/ownspce/backend/pkg/store"
	"golang.org/x/crypto/nacl/box"
)

// TestRoutesBuildWithoutConflict is the cheapest guard against a startup panic.
// chi mounts a subrouter over a whole subtree, so a second Mount on a path that
// already has one panics inside routes() — at boot, on every request, in
// production. Constructing the tree here catches that in a unit test with no
// database.
func TestRoutesBuildWithoutConflict(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("routes() panicked, which would take the API down at boot: %v", r)
		}
	}()
	if (&Server{}).routes() == nil {
		t.Fatal("routes() returned nil")
	}
}

// TestParseSealedAcceptsOnlyPaddedBuckets is the whole of the server's content
// validation. Padding is what stops a stored length from describing a ledger
// row — a 41-byte entry is a cup of coffee and a 300-byte one is a rent
// payment with a long note — so a payload that is not a bucket plus AEAD
// overhead has to be refused rather than quietly stored.
func TestParseSealedAcceptsOnlyPaddedBuckets(t *testing.T) {
	for _, bucket := range seal.MoneyBuckets {
		payload := encodeB64(make([]byte, bucket+seal.AEADOverhead))
		if _, err := parseSealed(payload, "ciphertext"); err != nil {
			t.Errorf("bucket %d rejected: %v", bucket, err)
		}
	}

	for _, size := range []int{1, 255, 256, 297, 1063, 4137, 8192} {
		if _, err := parseSealed(encodeB64(make([]byte, size)), "ciphertext"); err == nil {
			t.Errorf("%d bytes accepted, but it is not a bucket plus %d", size, seal.AEADOverhead)
		}
	}

	if _, err := parseSealed("", "ciphertext"); err == nil {
		t.Error("empty ciphertext accepted")
	}
	if _, err := parseSealed("not base64!!", "ciphertext"); err == nil {
		t.Error("malformed base64 accepted")
	}
}

// TestParseEntryCursorRoundTripsAPagePosition guards the keyset pagination the
// ledger feed uses. A cursor that parses loosely is worse than one that fails:
// it silently returns the wrong page.
func TestParseEntryCursorRoundTripsAPagePosition(t *testing.T) {
	id := uuid.New()
	date, parsedID, err := parseEntryCursor("2026-08-31|" + id.String())
	if err != nil {
		t.Fatalf("valid cursor rejected: %v", err)
	}
	if got := date.Format(dateFormat); got != "2026-08-31" {
		t.Errorf("date = %q, want 2026-08-31", got)
	}
	if parsedID != id {
		t.Errorf("id = %s, want %s", parsedID, id)
	}

	for _, bad := range []string{"", "2026-08-31", "|", "2026-08-31|nope", "31-08-2026|" + id.String(), id.String()} {
		if _, _, err := parseEntryCursor(bad); err == nil {
			t.Errorf("cursor %q accepted", bad)
		}
	}
}

func TestMintInviteTokenIsUnguessableAndStoredOnlyAsAHash(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 128; i++ {
		token, hash, err := mintInviteToken()
		if err != nil {
			t.Fatalf("mintInviteToken: %v", err)
		}
		if len(hash) != 32 {
			t.Fatalf("hash length = %d, want 32", len(hash))
		}
		if seen[token] {
			t.Fatalf("mintInviteToken repeated a token after %d draws", i)
		}
		seen[token] = true
		if string(hash) == token {
			t.Fatal("the stored hash equals the plaintext token")
		}
	}
}

// --- integration ---

func today() string { return time.Now().UTC().Format(dateFormat) }

func daysAgo(n int) string {
	return time.Now().UTC().AddDate(0, 0, -n).Format(dateFormat)
}

// sealed stands in for real ciphertext: the right length for the smallest money
// bucket, and opaque to everything on the server side.
func sealed(t *testing.T) string {
	t.Helper()
	return encodeB64(sealedPayload(t, seal.MoneyBuckets[0]))
}

// createHousehold makes a household with the space key wrapped for the actor's
// device, which is the only way one can be made.
func (h *harness) createHousehold(a *actor) string {
	h.t.Helper()
	body := map[string]any{
		"spaceId":     uuid.NewString(),
		"wrappedKeys": []map[string]any{{"deviceId": a.DeviceID.String(), "wrappedKey": wrappedKey(h.t)}},
		"ciphertext":  sealed(h.t),
	}
	rec := h.do(http.MethodPost, "/v1/money/households", a, body)
	requireStatus(h.t, rec, http.StatusCreated)
	return decodeBody(h.t, rec)["spaceId"].(string)
}

// putEntry writes one sealed ledger row and returns its client id.
func (h *harness) putEntry(a *actor, spaceID, occurredOn string) string {
	h.t.Helper()
	clientID := uuid.NewString()
	body := map[string]any{"entries": []map[string]any{{"clientId": clientID, "occurredOn": occurredOn, "ciphertext": sealed(h.t)}}}
	requireStatus(h.t, h.do(http.MethodPost, "/v1/money/households/"+spaceID+"/entries", a, body), http.StatusOK)
	return clientID
}

func (h *harness) listEntries(a *actor, spaceID, from, to string) []any {
	h.t.Helper()
	rec := h.do(http.MethodGet, fmt.Sprintf("/v1/money/households/%s/entries?from=%s&to=%s", spaceID, from, to), a, nil)
	requireStatus(h.t, rec, http.StatusOK)
	return decodeBody(h.t, rec)["entries"].([]any)
}

// TestCreateHouseholdRefusesToMakeOneNobodyCanOpen is the invariant the whole
// design rests on. A household whose key was never wrapped for a live device is
// permanently unreadable, and there is no server-side copy to fall back on, so
// the create has to fail rather than leave one behind.
func TestCreateHouseholdRefusesToMakeOneNobodyCanOpen(t *testing.T) {
	h := newHarness(t)
	owner := h.signUp("owner")
	stranger := h.signUp("stranger")

	body := map[string]any{
		"spaceId":     uuid.NewString(),
		"wrappedKeys": []map[string]any{{"deviceId": stranger.DeviceID.String(), "wrappedKey": wrappedKey(t)}},
		"ciphertext":  sealed(t),
	}
	requireStatus(t, h.do(http.MethodPost, "/v1/money/households", owner, body), http.StatusBadRequest)

	// And nothing was created: the owner still has no households.
	rec := h.do(http.MethodGet, "/v1/money/households", owner, nil)
	requireStatus(t, rec, http.StatusOK)
	if households := decodeBody(t, rec)["households"].([]any); len(households) != 0 {
		t.Fatalf("a household survived a rolled-back create: %s", rec.Body.String())
	}
}

// TestHouseholdIdIsClientMintedAndUniqueOnce pins the reason the client picks
// the id: the sealed settings document binds it, so it must exist before the
// household does. Reusing one is refused rather than merged into.
func TestHouseholdIdIsClientMintedAndUniqueOnce(t *testing.T) {
	h := newHarness(t)
	owner := h.signUp("owner")
	spaceID := uuid.NewString()

	body := map[string]any{
		"spaceId":     spaceID,
		"wrappedKeys": []map[string]any{{"deviceId": owner.DeviceID.String(), "wrappedKey": wrappedKey(t)}},
		"ciphertext":  sealed(t),
	}
	created := h.do(http.MethodPost, "/v1/money/households", owner, body)
	requireStatus(t, created, http.StatusCreated)
	if decodeBody(t, created)["spaceId"] != spaceID {
		t.Fatalf("server did not keep the client's id: %s", created.Body.String())
	}

	again := h.do(http.MethodPost, "/v1/money/households", owner, body)
	requireStatus(t, again, http.StatusConflict)
	if code := errorCode(t, again); code != "space_exists" {
		t.Errorf("code = %q, want space_exists", code)
	}

	requireStatus(t, h.do(http.MethodPost, "/v1/money/households", owner, map[string]any{
		"spaceId":     "not-a-uuid",
		"wrappedKeys": body["wrappedKeys"],
		"ciphertext":  sealed(t),
	}), http.StatusBadRequest)
}

// TestHouseholdListCarriesTheKeyForTheAskingDevice checks the one field that
// decides whether a device sees a ledger or a waiting screen.
func TestHouseholdListCarriesTheKeyForTheAskingDevice(t *testing.T) {
	h := newHarness(t)
	owner := h.signUp("owner")
	spaceID := h.createHousehold(owner)

	rec := h.do(http.MethodGet, "/v1/money/households", owner, nil)
	requireStatus(t, rec, http.StatusOK)
	households := decodeBody(t, rec)["households"].([]any)
	if len(households) != 1 {
		t.Fatalf("households = %d, want 1", len(households))
	}
	first := households[0].(map[string]any)
	if first["spaceId"] != spaceID {
		t.Errorf("spaceId = %v, want %s", first["spaceId"], spaceID)
	}
	if first["wrappedKey"] == nil {
		t.Error("the creating device got no wrapped key back")
	}
	if first["role"] != "owner" {
		t.Errorf("role = %v, want owner", first["role"])
	}
}

// TestEntryWritesAreIdempotentOnClientID is why the client mints the id. A
// dropped response over a patchy connection must not turn one dinner into two.
func TestEntryWritesAreIdempotentOnClientID(t *testing.T) {
	h := newHarness(t)
	owner := h.signUp("owner")
	spaceID := h.createHousehold(owner)
	clientID := uuid.NewString()

	first := map[string]any{"entries": []map[string]any{{"clientId": clientID, "occurredOn": today(), "ciphertext": sealed(t)}}}
	requireStatus(t, h.do(http.MethodPost, "/v1/money/households/"+spaceID+"/entries", owner, first), http.StatusOK)

	replacement := sealed(t)
	second := map[string]any{"entries": []map[string]any{{"clientId": clientID, "occurredOn": today(), "ciphertext": replacement}}}
	requireStatus(t, h.do(http.MethodPost, "/v1/money/households/"+spaceID+"/entries", owner, second), http.StatusOK)

	entries := h.listEntries(owner, spaceID, today(), today())
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1 — the retry logged a second row", len(entries))
	}
	if got := entries[0].(map[string]any)["ciphertext"]; got != replacement {
		t.Error("the second write did not replace the first")
	}
}

// TestBatchRejectsARepeatedClientID guards against a batch deadlocking on
// itself: two upserts of one key inside a single transaction wait on each other
// forever, which is a hung request rather than an error the client can act on.
func TestBatchRejectsARepeatedClientID(t *testing.T) {
	h := newHarness(t)
	owner := h.signUp("owner")
	spaceID := h.createHousehold(owner)
	clientID := uuid.NewString()

	body := map[string]any{"entries": []map[string]any{
		{"clientId": clientID, "occurredOn": today(), "ciphertext": sealed(t)},
		{"clientId": clientID, "occurredOn": today(), "ciphertext": sealed(t)},
	}}
	requireStatus(t, h.do(http.MethodPost, "/v1/money/households/"+spaceID+"/entries", owner, body), http.StatusBadRequest)
}

// TestUnpaddedCiphertextIsRefused proves padding is enforced at the edge and not
// merely documented.
func TestUnpaddedCiphertextIsRefused(t *testing.T) {
	h := newHarness(t)
	owner := h.signUp("owner")
	spaceID := h.createHousehold(owner)

	body := map[string]any{"entries": []map[string]any{{"clientId": uuid.NewString(), "occurredOn": today(), "ciphertext": encodeB64(randomBytes(t, 200))}}}
	rec := h.do(http.MethodPost, "/v1/money/households/"+spaceID+"/entries", owner, body)
	requireStatus(t, rec, http.StatusRequestEntityTooLarge)
	if code := errorCode(t, rec); code != "bucket_violation" {
		t.Errorf("code = %q, want bucket_violation", code)
	}
}

// TestLedgerPagesWithoutRepeatingOrSkippingEntries covers keyset pagination
// across a date boundary, where an offset-based pager would drift as entries
// arrive mid-scroll.
func TestLedgerPagesWithoutRepeatingOrSkippingEntries(t *testing.T) {
	h := newHarness(t)
	owner := h.signUp("owner")
	spaceID := h.createHousehold(owner)

	const total = 7
	for i := 0; i < total; i++ {
		h.putEntry(owner, spaceID, daysAgo(i%3))
	}

	seen := map[string]bool{}
	cursor := ""
	for page := 0; page < 10; page++ {
		path := fmt.Sprintf("/v1/money/households/%s/entries?from=%s&to=%s&limit=3", spaceID, daysAgo(30), today())
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		rec := h.do(http.MethodGet, path, owner, nil)
		requireStatus(t, rec, http.StatusOK)
		body := decodeBody(t, rec)

		for _, raw := range body["entries"].([]any) {
			id := raw.(map[string]any)["id"].(string)
			if seen[id] {
				t.Fatalf("entry %s appeared on two pages", id)
			}
			seen[id] = true
		}
		cursor, _ = body["nextCursor"].(string)
		if cursor == "" {
			break
		}
	}
	if len(seen) != total {
		t.Fatalf("paged through %d entries, wrote %d", len(seen), total)
	}
}

// TestDeletedEntryLeavesTheFeed checks the tombstone actually hides the row.
func TestDeletedEntryLeavesTheFeed(t *testing.T) {
	h := newHarness(t)
	owner := h.signUp("owner")
	spaceID := h.createHousehold(owner)
	clientID := h.putEntry(owner, spaceID, today())

	requireStatus(t, h.do(http.MethodDelete, "/v1/money/households/"+spaceID+"/entries/"+clientID, owner, nil), http.StatusNoContent)
	if entries := h.listEntries(owner, spaceID, today(), today()); len(entries) != 0 {
		t.Fatalf("deleted entry still in the feed: %d rows", len(entries))
	}

	// Deleting twice is not an error: an offline client replaying its queue
	// must not be told its own successful delete failed.
	requireStatus(t, h.do(http.MethodDelete, "/v1/money/households/"+spaceID+"/entries/"+clientID, owner, nil), http.StatusNoContent)
}

// TestVaultConcurrencyStopsASilentOverwrite covers two members editing
// household rules at once.
func TestVaultConcurrencyStopsASilentOverwrite(t *testing.T) {
	h := newHarness(t)
	owner := h.signUp("owner")
	spaceID := h.createHousehold(owner)

	rec := h.do(http.MethodGet, "/v1/money/households/"+spaceID+"/vault", owner, nil)
	requireStatus(t, rec, http.StatusOK)
	body := decodeBody(t, rec)
	version := int64(body["version"].(float64))
	epoch := int(body["keyEpoch"].(float64))

	update := map[string]any{"version": version, "keyEpoch": epoch, "ciphertext": sealed(t)}
	requireStatus(t, h.do(http.MethodPut, "/v1/money/households/"+spaceID+"/vault", owner, update), http.StatusOK)

	// The same version again is a stale write, and is refused.
	stale := h.do(http.MethodPut, "/v1/money/households/"+spaceID+"/vault", owner, update)
	requireStatus(t, stale, http.StatusConflict)
	if code := errorCode(t, stale); code != "version_conflict" {
		t.Errorf("code = %q, want version_conflict", code)
	}
}

// TestObjectsRoundTripPerKind covers the non-ledger records.
func TestObjectsRoundTripPerKind(t *testing.T) {
	h := newHarness(t)
	owner := h.signUp("owner")
	spaceID := h.createHousehold(owner)

	categoryID := uuid.NewString()
	body := map[string]any{"objects": []map[string]any{
		{"kind": "category", "clientId": categoryID, "sortOrder": 0, "ciphertext": sealed(t)},
		{"kind": "budget", "clientId": uuid.NewString(), "sortOrder": 0, "ciphertext": sealed(t)},
	}}
	requireStatus(t, h.do(http.MethodPost, "/v1/money/households/"+spaceID+"/objects", owner, body), http.StatusOK)

	rec := h.do(http.MethodGet, "/v1/money/households/"+spaceID+"/objects?kind=category", owner, nil)
	requireStatus(t, rec, http.StatusOK)
	objects := decodeBody(t, rec)["objects"].([]any)
	if len(objects) != 1 || objects[0].(map[string]any)["clientId"] != categoryID {
		t.Fatalf("kind filter did not narrow the list: %s", rec.Body.String())
	}

	all := h.do(http.MethodGet, "/v1/money/households/"+spaceID+"/objects", owner, nil)
	requireStatus(t, all, http.StatusOK)
	if got := len(decodeBody(t, all)["objects"].([]any)); got != 2 {
		t.Fatalf("unfiltered objects = %d, want 2", got)
	}

	requireStatus(t, h.do(http.MethodDelete, "/v1/money/households/"+spaceID+"/objects/category/"+categoryID, owner, nil), http.StatusNoContent)
	after := h.do(http.MethodGet, "/v1/money/households/"+spaceID+"/objects?kind=category", owner, nil)
	requireStatus(t, after, http.StatusOK)
	if got := len(decodeBody(t, after)["objects"].([]any)); got != 0 {
		t.Fatalf("deleted category still listed: %d", got)
	}

	requireStatus(t, h.do(http.MethodGet, "/v1/money/households/"+spaceID+"/objects?kind=nonsense", owner, nil), http.StatusBadRequest)
}

// TestNonMemberCannotReachAHousehold is the access-control floor: without a
// membership row, a household must not even be distinguishable from one that
// does not exist.
func TestNonMemberCannotReachAHousehold(t *testing.T) {
	h := newHarness(t)
	owner := h.signUp("owner")
	stranger := h.signUp("stranger")
	spaceID := h.createHousehold(owner)

	for _, path := range []string{"/vault", "/entries?from=" + today() + "&to=" + today(), "/objects", "/key-gaps"} {
		rec := h.do(http.MethodGet, "/v1/money/households/"+spaceID+path, stranger, nil)
		requireStatus(t, rec, http.StatusNotFound)
	}
	body := map[string]any{"entries": []map[string]any{{"clientId": uuid.NewString(), "occurredOn": today(), "ciphertext": sealed(t)}}}
	requireStatus(t, h.do(http.MethodPost, "/v1/money/households/"+spaceID+"/entries", stranger, body), http.StatusNotFound)
}

// TestInviteCarriesTheHouseholdKey is the whole of the new collaboration flow,
// end to end.
//
// It used to be that redeeming an invite was permission to be handed the ledger
// and not the ledger: the invitee became a member, saw rows they could not open,
// and waited for an owner to next open Money and wrap the key for them. That
// wait was the worst screen in the product, because nothing on it was
// actionable by the person looking at it.
//
// Now the key travels with the invite. Creating one provisions the invited
// address an escrow identity; the owner — the only party holding the household
// key in the clear — seals it to that identity while they still have it; and
// the invitee signs in and reads the ledger on first paint, having approved
// nothing and waited for nobody. If this test passes with the original space
// key coming back out, that promise holds.
func TestInviteCarriesTheHouseholdKey(t *testing.T) {
	// Arrange — a household whose key is wrapped for the owner's device and for
	// the owner's account escrow key, which is what a client does at creation.
	h := newHarness(t)
	owner := h.signUp("owner")
	ownerEscrow := h.escrowPublicKey(t, owner.UserID)

	spaceKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, spaceKey); err != nil {
		t.Fatalf("random space key: %v", err)
	}
	var ownerDevicePublic [32]byte
	copy(ownerDevicePublic[:], owner.PublicKey)

	spaceID := uuid.NewString()
	requireStatus(t, h.do(http.MethodPost, "/v1/money/households", owner, map[string]any{
		"spaceId": spaceID,
		"wrappedKeys": []map[string]any{
			{"deviceId": owner.DeviceID.String(), "wrappedKey": encodeB64(sealTo(t, spaceKey, ownerDevicePublic))},
			{"wrappedKey": encodeB64(sealTo(t, spaceKey, ownerEscrow))},
		},
		"ciphertext": sealed(t),
	}), http.StatusCreated)
	h.putEntry(owner, spaceID, today())

	// Act, part one — invite an address nobody has ever signed in with.
	guestEmail := fmt.Sprintf("amma-%s@ownspce.test", uuid.NewString())
	rec := h.do(http.MethodPost, "/v1/money/households/"+spaceID+"/invites", owner, map[string]any{"email": guestEmail, "role": "editor"})
	requireStatus(t, rec, http.StatusCreated)
	invite := decodeBody(t, rec)

	guestID, ok := invite["userId"].(string)
	if !ok || guestID == "" {
		t.Fatal("the invite provisioned no account to seal the household key to")
	}
	h.users = append(h.users, uuid.MustParse(guestID))

	rawEscrow, ok := invite["escrowPublicKey"].(string)
	if !ok || rawEscrow == "" {
		t.Fatal("the invite carried no escrow public key, so the household key cannot travel with it")
	}
	var guestEscrow [32]byte
	copy(guestEscrow[:], decodeKey(t, rawEscrow))

	// The same address twice is a conflict, not a second live invite.
	requireStatus(t, h.do(http.MethodPost, "/v1/money/households/"+spaceID+"/invites", owner, map[string]any{"email": guestEmail}), http.StatusConflict)

	// Act, part two — the owner seals the household key to that identity.
	epoch := int(invite["keyEpoch"].(float64))
	filed := h.do(http.MethodPost, "/v1/money/households/"+spaceID+"/invites/"+invite["id"].(string)+"/key", owner, map[string]any{
		"keyEpoch":   epoch,
		"wrappedKey": encodeB64(sealTo(t, spaceKey, guestEscrow)),
	})
	requireStatus(t, filed, http.StatusOK)

	// Act, part three — the invitee signs in for the very first time.
	guestPublic, guestPrivate := deviceKeypair(t)
	code := h.issueSignInCode(guestEmail, nil)
	session := h.doFrom(http.MethodPost, "/v1/auth/session", nil, sessionBody(guestEmail, code, guestPublic[:]))
	requireStatus(t, session, http.StatusOK)
	body := decodeBody(t, session)
	if device := body["device"].(map[string]any); device["status"] != store.DeviceStatusActive {
		t.Fatalf("the invitee's first device status = %v, want active", device["status"])
	}
	guest := &actor{UserID: uuid.MustParse(guestID), Token: body["accessToken"].(string), PublicKey: guestPublic[:]}

	// Assert — a member, with a key, on first paint. No approval, no waiting.
	list := h.do(http.MethodGet, "/v1/money/households", guest, nil)
	requireStatus(t, list, http.StatusOK)
	households := decodeBody(t, list)["households"].([]any)
	if len(households) != 1 {
		t.Fatalf("the invitee sees %d households, want 1", len(households))
	}
	household := households[0].(map[string]any)
	if household["spaceId"] != spaceID {
		t.Fatalf("landed in %v, want %s", household["spaceId"], spaceID)
	}
	if household["role"] != "editor" {
		t.Fatalf("role = %v, want editor", household["role"])
	}

	wrapped, ok := household["wrappedKey"].(string)
	if !ok || wrapped == "" {
		t.Fatal("the invitee was let in without a household key, which is the screen this change exists to delete")
	}
	opened, ok := box.OpenAnonymous(nil, decodeKey(t, wrapped), &guestPublic, &guestPrivate)
	if !ok {
		t.Fatal("the invitee could not open the key they were given")
	}
	if !bytes.Equal(opened, spaceKey) {
		t.Fatal("the invitee opened a different key than the household was sealed with")
	}

	// And the ledger behind it is readable.
	entries := h.do(http.MethodGet, "/v1/money/households/"+spaceID+"/entries?from="+daysAgo(1)+"&to="+today(), guest, nil)
	requireStatus(t, entries, http.StatusOK)
	if rows := decodeBody(t, entries)["entries"].([]any); len(rows) != 1 {
		t.Fatalf("the invitee sees %d ledger rows, want 1", len(rows))
	}

	// The invite is spent: it no longer sits in the owner's outstanding list.
	open := h.do(http.MethodGet, "/v1/money/households/"+spaceID+"/invites", owner, nil)
	requireStatus(t, open, http.StatusOK)
	if invites := decodeBody(t, open)["invites"].([]any); len(invites) != 0 {
		t.Fatalf("%d invites still outstanding after the key landed, want 0", len(invites))
	}
}

// TestFilingAnInviteKeyTwiceIsRefused stops a replayed wrap from re-adding
// somebody an owner has since removed from the household.
func TestFilingAnInviteKeyTwiceIsRefused(t *testing.T) {
	// Arrange
	h := newHarness(t)
	owner := h.signUp("owner")
	ownerEscrow := h.escrowPublicKey(t, owner.UserID)

	spaceKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, spaceKey); err != nil {
		t.Fatalf("random space key: %v", err)
	}
	var ownerDevicePublic [32]byte
	copy(ownerDevicePublic[:], owner.PublicKey)

	spaceID := uuid.NewString()
	requireStatus(t, h.do(http.MethodPost, "/v1/money/households", owner, map[string]any{
		"spaceId": spaceID,
		"wrappedKeys": []map[string]any{
			{"deviceId": owner.DeviceID.String(), "wrappedKey": encodeB64(sealTo(t, spaceKey, ownerDevicePublic))},
			{"wrappedKey": encodeB64(sealTo(t, spaceKey, ownerEscrow))},
		},
		"ciphertext": sealed(t),
	}), http.StatusCreated)

	rec := h.do(http.MethodPost, "/v1/money/households/"+spaceID+"/invites", owner, map[string]any{"email": fmt.Sprintf("twice-%s@ownspce.test", uuid.NewString())})
	requireStatus(t, rec, http.StatusCreated)
	invite := decodeBody(t, rec)
	h.users = append(h.users, uuid.MustParse(invite["userId"].(string)))

	var guestEscrow [32]byte
	copy(guestEscrow[:], decodeKey(t, invite["escrowPublicKey"].(string)))
	path := "/v1/money/households/" + spaceID + "/invites/" + invite["id"].(string) + "/key"
	body := map[string]any{"keyEpoch": int(invite["keyEpoch"].(float64)), "wrappedKey": encodeB64(sealTo(t, spaceKey, guestEscrow))}

	// Act
	requireStatus(t, h.do(http.MethodPost, path, owner, body), http.StatusOK)
	replay := h.do(http.MethodPost, path, owner, body)

	// Assert — and a wrap computed against a rotated epoch is refused too.
	requireStatus(t, replay, http.StatusNotFound)

	fresh := h.do(http.MethodPost, "/v1/money/households/"+spaceID+"/invites", owner, map[string]any{"email": fmt.Sprintf("stale-%s@ownspce.test", uuid.NewString())})
	requireStatus(t, fresh, http.StatusCreated)
	staleInvite := decodeBody(t, fresh)
	h.users = append(h.users, uuid.MustParse(staleInvite["userId"].(string)))
	copy(guestEscrow[:], decodeKey(t, staleInvite["escrowPublicKey"].(string)))

	stale := h.do(http.MethodPost, "/v1/money/households/"+spaceID+"/invites/"+staleInvite["id"].(string)+"/key", owner, map[string]any{
		"keyEpoch":   int(staleInvite["keyEpoch"].(float64)) + 1,
		"wrappedKey": encodeB64(sealTo(t, spaceKey, guestEscrow)),
	})
	requireStatus(t, stale, http.StatusConflict)
	if code := errorCode(t, stale); code != "stale_epoch" {
		t.Errorf("code = %q, want stale_epoch", code)
	}
}

func TestForgedInviteTokenIsRejected(t *testing.T) {
	h := newHarness(t)
	a := h.signUp("owner")

	for _, token := range []string{"", "oski_", "oski_" + uuid.NewString(), "not-a-token"} {
		requireStatus(t, h.do(http.MethodPost, "/v1/money/invites/accept", a, map[string]any{"token": token}), http.StatusNotFound)
	}
}

// TestKeysCannotBeGrantedToSomeoneElsesDevice stops the grant path from being a
// way to file a wrap against a device its owner never registered.
func TestKeysCannotBeGrantedToSomeoneElsesDevice(t *testing.T) {
	h := newHarness(t)
	owner := h.signUp("owner")
	stranger := h.signUp("stranger")
	spaceID := h.createHousehold(owner)

	grant := map[string]any{"keyEpoch": 1, "wrappedKeys": []map[string]any{{"userId": stranger.UserID.String(), "deviceId": stranger.DeviceID.String(), "wrappedKey": wrappedKey(t)}}}
	requireStatus(t, h.do(http.MethodPost, "/v1/money/households/"+spaceID+"/keys", owner, grant), http.StatusBadRequest)

	stale := map[string]any{"keyEpoch": 9, "wrappedKeys": []map[string]any{{"userId": owner.UserID.String(), "deviceId": owner.DeviceID.String(), "wrappedKey": wrappedKey(t)}}}
	rec := h.do(http.MethodPost, "/v1/money/households/"+spaceID+"/keys", owner, stale)
	requireStatus(t, rec, http.StatusConflict)
	if code := errorCode(t, rec); code != "stale_epoch" {
		t.Errorf("code = %q, want stale_epoch", code)
	}
}

// TestViewerCannotWriteAndEditorCannotGrantKeys pins the role boundaries that
// matter: a viewer changes nothing, and handing the ledger to a new device stays
// with the owner.
func TestViewerCannotWriteAndEditorCannotGrantKeys(t *testing.T) {
	h := newHarness(t)
	owner := h.signUp("owner")
	viewer := h.signUp("viewer")
	editor := h.signUp("editor")
	spaceID := h.createHousehold(owner)

	for _, join := range []struct {
		a    *actor
		role string
	}{{viewer, "viewer"}, {editor, "editor"}} {
		rec := h.do(http.MethodPost, "/v1/money/households/"+spaceID+"/invites", owner, map[string]any{"email": uuid.NewString() + "@home.in", "role": join.role})
		requireStatus(t, rec, http.StatusCreated)
		token := decodeBody(t, rec)["token"].(string)
		requireStatus(t, h.do(http.MethodPost, "/v1/money/invites/accept", join.a, map[string]any{"token": token}), http.StatusOK)
	}

	write := map[string]any{"entries": []map[string]any{{"clientId": uuid.NewString(), "occurredOn": today(), "ciphertext": sealed(t)}}}
	requireStatus(t, h.do(http.MethodPost, "/v1/money/households/"+spaceID+"/entries", viewer, write), http.StatusForbidden)
	requireStatus(t, h.do(http.MethodPost, "/v1/money/households/"+spaceID+"/entries", editor, write), http.StatusOK)

	grant := map[string]any{"keyEpoch": 1, "wrappedKeys": []map[string]any{{"userId": editor.UserID.String(), "deviceId": editor.DeviceID.String(), "wrappedKey": wrappedKey(t)}}}
	requireStatus(t, h.do(http.MethodPost, "/v1/money/households/"+spaceID+"/keys", editor, grant), http.StatusForbidden)
	requireStatus(t, h.do(http.MethodPost, "/v1/money/households/"+spaceID+"/invites", editor, map[string]any{"email": "x@home.in"}), http.StatusForbidden)
}

// TestASecondBrowserReachesTheLedgerImmediately is the money side of device
// approval being gone. A second browser used to land pending and be refused
// every money route; it is now in the account from the moment it registers, and
// what it can read is decided by the keys wrapped for it rather than by a
// waiting room.
func TestASecondBrowserReachesTheLedgerImmediately(t *testing.T) {
	h := newHarness(t)
	owner := h.signUp("owner")
	spaceID := h.createHousehold(owner)

	second := h.addDevice(owner.UserID, "second browser")
	if second.Status != store.DeviceStatusActive {
		t.Fatalf("second device status = %q, want active", second.Status)
	}

	list := h.do(http.MethodGet, "/v1/money/households", second, nil)
	requireStatus(t, list, http.StatusOK)
	requireStatus(t, h.do(http.MethodGet, "/v1/money/households/"+spaceID+"/vault", second, nil), http.StatusOK)

	// This household was created with a device wrap only, so there is nothing in
	// escrow to restore and the browser is in without being able to read a row.
	// That is honest, and it is the case the key-gaps repair path exists for.
	households := decodeBody(t, list)["households"].([]any)
	if len(households) != 1 {
		t.Fatalf("got %d households, want 1", len(households))
	}
	if households[0].(map[string]any)["wrappedKey"] != nil {
		t.Error("a household with no escrow copy handed a key to a device nobody wrapped one for")
	}
}

// TestEntryRangeBoundsAreValidated keeps a malformed period from being read as
// "everything".
func TestEntryRangeBoundsAreValidated(t *testing.T) {
	h := newHarness(t)
	owner := h.signUp("owner")
	spaceID := h.createHousehold(owner)
	base := "/v1/money/households/" + spaceID + "/entries"

	for _, query := range []string{"", "?from=" + today(), "?to=" + today(), "?from=31-08-2026&to=" + today(), "?from=" + today() + "&to=" + daysAgo(5)} {
		requireStatus(t, h.do(http.MethodGet, base+query, owner, nil), http.StatusBadRequest)
	}
	requireStatus(t, h.do(http.MethodGet, base+"?from="+daysAgo(5)+"&to="+today()+"&limit=0", owner, nil), http.StatusBadRequest)
	requireStatus(t, h.do(http.MethodGet, base+"?from="+daysAgo(5)+"&to="+today()+"&limit=501", owner, nil), http.StatusBadRequest)
}

// TestADeviceCannotFileItsOwnKeys keeps the one part of approval that still
// means something. A device is in the account the moment it signs in, but the
// keys it holds have to have been wrapped by somebody who held the plaintext —
// itself included would make the whole scheme decorative, since a device could
// then file wraps for spaces it was never given. The only self-service route
// left is a mailed code, where the server does the wrapping from escrow.
func TestADeviceCannotFileItsOwnKeys(t *testing.T) {
	h := newHarness(t)
	owner := h.signUp("owner")
	h.createHousehold(owner)

	second := h.addDevice(owner.UserID, "attacker browser")
	path := "/v1/devices/" + second.DeviceID.String() + "/approve"

	// Act
	empty := h.do(http.MethodPost, path, second, map[string]any{"wrappedKeys": []any{}})

	// Assert
	requireStatus(t, empty, http.StatusForbidden)
	if code := errorCode(t, empty); code != "approval_required" {
		t.Errorf("code = %q, want approval_required", code)
	}

	// Supplying wraps it invented does not help either.
	invented := h.do(http.MethodPost, path, second, map[string]any{"wrappedKeys": []map[string]any{
		{"spaceId": uuid.NewString(), "keyEpoch": 1, "wrappedKey": wrappedKey(t)},
	}})
	requireStatus(t, invented, http.StatusForbidden)

	var keys int
	if err := h.store.Pool().QueryRow(context.Background(), "SELECT count(*) FROM space_keys WHERE device_id = $1", second.DeviceID).Scan(&keys); err != nil {
		t.Fatalf("count space keys: %v", err)
	}
	if keys != 0 {
		t.Fatalf("a refused self-approval still filed %d space keys", keys)
	}
}
