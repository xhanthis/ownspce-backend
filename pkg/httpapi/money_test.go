package httpapi

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ownspce/backend/pkg/seal"
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

// TestInviteMakesAMemberWhoStillHoldsNoKey is the shape of collaboration under
// end-to-end encryption, and the part most likely to be got wrong. Redeeming an
// invite is permission to be handed the ledger; it is not the ledger. Until an
// owner wraps the space key for the new member's device, they can read the rows
// and open none of them.
func TestInviteMakesAMemberWhoStillHoldsNoKey(t *testing.T) {
	h := newHarness(t)
	owner := h.signUp("owner")
	guest := h.signUp("guest")
	spaceID := h.createHousehold(owner)
	h.putEntry(owner, spaceID, today())

	rec := h.do(http.MethodPost, "/v1/money/households/"+spaceID+"/invites", owner, map[string]any{"email": "amma@home.in", "role": "editor"})
	requireStatus(t, rec, http.StatusCreated)
	token := decodeBody(t, rec)["token"].(string)

	// The same address twice is a conflict, not a second live invite.
	requireStatus(t, h.do(http.MethodPost, "/v1/money/households/"+spaceID+"/invites", owner, map[string]any{"email": "amma@home.in"}), http.StatusConflict)

	accepted := h.do(http.MethodPost, "/v1/money/invites/accept", guest, map[string]any{"token": token})
	requireStatus(t, accepted, http.StatusOK)
	if decodeBody(t, accepted)["awaitingKey"] != true {
		t.Error("accepting an invite did not say the ledger is still locked")
	}

	// A member, but keyless: the household lists with a null wrappedKey.
	list := h.do(http.MethodGet, "/v1/money/households", guest, nil)
	requireStatus(t, list, http.StatusOK)
	households := decodeBody(t, list)["households"].([]any)
	if len(households) != 1 {
		t.Fatalf("guest sees %d households, want 1", len(households))
	}
	if households[0].(map[string]any)["wrappedKey"] != nil {
		t.Fatal("a freshly invited member was handed a space key")
	}

	// The owner sees exactly that gap, wraps, and files it.
	gapsRec := h.do(http.MethodGet, "/v1/money/households/"+spaceID+"/key-gaps", owner, nil)
	requireStatus(t, gapsRec, http.StatusOK)
	var guestGap map[string]any
	for _, raw := range decodeBody(t, gapsRec)["gaps"].([]any) {
		gap := raw.(map[string]any)
		if gap["userId"] == guest.UserID.String() && gap["deviceId"] != nil {
			guestGap = gap
		}
	}
	if guestGap == nil {
		t.Fatal("the new member's device was not reported as a key gap")
	}

	grant := map[string]any{"keyEpoch": 1, "wrappedKeys": []map[string]any{{"userId": guest.UserID.String(), "deviceId": guestGap["deviceId"], "wrappedKey": wrappedKey(t)}}}
	requireStatus(t, h.do(http.MethodPost, "/v1/money/households/"+spaceID+"/keys", owner, grant), http.StatusOK)

	after := h.do(http.MethodGet, "/v1/money/households", guest, nil)
	requireStatus(t, after, http.StatusOK)
	if decodeBody(t, after)["households"].([]any)[0].(map[string]any)["wrappedKey"] == nil {
		t.Fatal("the granted key did not reach the member's device")
	}

	// A spent token cannot be redeemed again.
	third := h.signUp("third")
	requireStatus(t, h.do(http.MethodPost, "/v1/money/invites/accept", third, map[string]any{"token": token}), http.StatusNotFound)
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

// TestPendingDeviceIsKeptOutOfTheLedger checks money now sits behind device
// approval. A second browser lands pending, and pending devices hold no space
// key — letting one in would show a wall of ciphertext, not a ledger.
func TestPendingDeviceIsKeptOutOfTheLedger(t *testing.T) {
	h := newHarness(t)
	owner := h.signUp("owner")
	spaceID := h.createHousehold(owner)

	second := h.addDevice(owner.UserID, "second browser")
	if second.Status != "pending" {
		t.Fatalf("second device status = %q, want pending", second.Status)
	}
	requireStatus(t, h.do(http.MethodGet, "/v1/money/households", second, nil), http.StatusForbidden)
	requireStatus(t, h.do(http.MethodGet, "/v1/money/households/"+spaceID+"/vault", second, nil), http.StatusForbidden)
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

// TestPendingDeviceCannotSelfApproveWithoutRecoveryCoverage closes the hole that
// would make device approval decorative. Money now sits behind an active device,
// so a pending device that could activate itself by asserting "recovery" with an
// empty key list would walk straight past the gate.
func TestPendingDeviceCannotSelfApproveWithoutRecoveryCoverage(t *testing.T) {
	h := newHarness(t)
	owner := h.signUp("owner")
	h.createHousehold(owner)

	pending := h.addDevice(owner.UserID, "attacker browser")
	path := "/v1/devices/" + pending.DeviceID.String() + "/approve"

	// No recovery key on the account at all: recovery cannot be the way in.
	empty := h.do(http.MethodPost, path, pending, map[string]any{"recovery": true, "wrappedKeys": []any{}})
	requireStatus(t, empty, http.StatusForbidden)
	if code := errorCode(t, empty); code != "no_recovery_key" {
		t.Errorf("code = %q, want no_recovery_key", code)
	}

	// Still pending, and still locked out of the ledger.
	requireStatus(t, h.do(http.MethodGet, "/v1/money/households", pending, nil), http.StatusForbidden)

	// With a recovery key on file, a claim that skips a space is refused too.
	requireStatus(t, h.do(http.MethodPatch, "/v1/me", owner, map[string]any{"recoveryPublicKey": encodeB64(randomBytes(t, seal.PublicKeySize))}), http.StatusOK)
	h.createSpaceWithRecovery(owner)

	short := h.do(http.MethodPost, path, pending, map[string]any{"recovery": true, "wrappedKeys": []any{}})
	requireStatus(t, short, http.StatusForbidden)
	if code := errorCode(t, short); code != "incomplete_recovery" {
		t.Errorf("code = %q, want incomplete_recovery", code)
	}

	// And a claim that covers every recovery-wrapped space is admitted, because
	// the server cannot check a phrase — only that the claim is possible.
	wraps := h.do(http.MethodGet, "/v1/recovery/spaces", pending, nil)
	requireStatus(t, wraps, http.StatusOK)
	covering := make([]map[string]any, 0)
	for _, raw := range decodeBody(t, wraps)["spaces"].([]any) {
		space := raw.(map[string]any)
		covering = append(covering, map[string]any{"spaceId": space["spaceId"], "keyEpoch": space["keyEpoch"], "wrappedKey": wrappedKey(t)})
	}
	requireStatus(t, h.do(http.MethodPost, path, pending, map[string]any{"recovery": true, "wrappedKeys": covering}), http.StatusOK)
}
