package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ownspce/backend/pkg/config"
	"github.com/ownspce/backend/pkg/dotenv"
	"github.com/ownspce/backend/pkg/seal"
	"github.com/ownspce/backend/pkg/store"
)

// The integration suite talks to a real Neon database, so it only runs when
// OWNSPCE_TEST_DB=1 is set. Every test creates its own users and deletes them
// afterwards; user deletion cascades to devices, spaces, logs and publishes.

type harness struct {
	t      *testing.T
	server *Server
	store  *store.Store
	users  []uuid.UUID
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	if os.Getenv("OWNSPCE_TEST_DB") != "1" {
		t.Skip("set OWNSPCE_TEST_DB=1 to run integration tests against the database")
	}
	dotenv.Load("../../.env")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	st, err := store.Open(context.Background(), cfg.DatabaseURL)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}

	h := &harness{t: t, server: New(cfg, st), store: st}
	t.Cleanup(h.cleanup)
	return h
}

func (h *harness) cleanup() {
	for _, id := range h.users {
		if _, err := h.store.Pool().Exec(context.Background(), "DELETE FROM users WHERE id = $1", id); err != nil {
			h.t.Logf("cleanup user %s: %v", id, err)
		}
	}
	h.store.Close()
}

// actor is a signed-in device: an auth identity plus the device key that would
// hold the decryption keys on a real client.
type actor struct {
	UserID    uuid.UUID
	DeviceID  uuid.UUID
	PublicKey []byte
	Token     string
	Status    string
}

// signUp creates a user and registers a device, mirroring what POST /auth/session
// does after an ID token verifies. It bypasses only the provider verification,
// which oidc_test.go covers separately.
func (h *harness) signUp(label string) *actor {
	h.t.Helper()
	ctx := context.Background()
	email := fmt.Sprintf("test-%s@ownspce.test", uuid.NewString())

	user, _, err := h.store.UpsertUserByProvider(ctx, "google", "sub-"+uuid.NewString(), email, label, "")
	if err != nil {
		h.t.Fatalf("create user: %v", err)
	}
	h.users = append(h.users, user.ID)

	return h.addDevice(user.ID, label)
}

func (h *harness) addDevice(userID uuid.UUID, label string) *actor {
	h.t.Helper()
	publicKey := randomBytes(h.t, seal.PublicKeySize)

	device, err := h.store.RegisterDevice(context.Background(), userID, label, "macos", publicKey)
	if err != nil {
		h.t.Fatalf("register device: %v", err)
	}
	token, _, err := h.server.signer.Mint(userID, device.ID)
	if err != nil {
		h.t.Fatalf("mint token: %v", err)
	}
	return &actor{UserID: userID, DeviceID: device.ID, PublicKey: publicKey, Token: token, Status: device.Status}
}

func (h *harness) do(method, path string, a *actor, body any) *httptest.ResponseRecorder {
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
	rec := httptest.NewRecorder()
	h.server.ServeHTTP(rec, req)
	return rec
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response %q: %v", rec.Body.String(), err)
	}
	return out
}

func requireStatus(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, want, rec.Body.String())
	}
}

func errorCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var payload struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode error body %q: %v", rec.Body.String(), err)
	}
	return payload.Error.Code
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("random bytes: %v", err)
	}
	return b
}

// sealedPayload produces a byte string with the exact length of a padded bucket
// plus AEAD overhead, standing in for real ciphertext.
func sealedPayload(t *testing.T, bucket int) []byte {
	t.Helper()
	return randomBytes(t, bucket+seal.AEADOverhead)
}

func wrappedKey(t *testing.T) string {
	t.Helper()
	return encodeB64(randomBytes(t, 80))
}

// createSpace creates a space with the key wrapped for the actor's device.
func (h *harness) createSpace(a *actor) string {
	h.t.Helper()
	deviceID := a.DeviceID.String()
	rec := h.do(http.MethodPost, "/v1/spaces", a, map[string]any{"wrappedKeys": []map[string]any{{"deviceId": deviceID, "wrappedKey": wrappedKey(h.t)}}})
	requireStatus(h.t, rec, http.StatusCreated)
	return decodeBody(h.t, rec)["id"].(string)
}

func TestHealthReportsDatabaseReachable(t *testing.T) {
	h := newHarness(t)

	rec := h.do(http.MethodGet, "/v1/health", nil, nil)

	requireStatus(t, rec, http.StatusOK)
	if decodeBody(t, rec)["status"] != "ok" {
		t.Errorf("unexpected health body: %s", rec.Body.String())
	}
}

func TestProfileUpdateAndUsernameRules(t *testing.T) {
	// Arrange
	h := newHarness(t)
	first := h.signUp("first")
	second := h.signUp("second")
	username := "u" + uuid.NewString()[:8]

	// Act
	rec := h.do(http.MethodPatch, "/v1/me", first, map[string]any{"username": username, "theme": "dark", "font": "serif", "palette": "sand"})

	// Assert
	requireStatus(t, rec, http.StatusOK)
	body := decodeBody(t, rec)
	if body["username"] != username || body["theme"] != "dark" {
		t.Fatalf("profile not updated: %s", rec.Body.String())
	}
	if body["font"] != "serif" || body["palette"] != "sand" {
		t.Fatalf("appearance not updated: %s", rec.Body.String())
	}

	badFont := h.do(http.MethodPatch, "/v1/me", first, map[string]any{"font": "comic"})
	requireStatus(t, badFont, http.StatusBadRequest)

	badPalette := h.do(http.MethodPatch, "/v1/me", first, map[string]any{"palette": "neon"})
	requireStatus(t, badPalette, http.StatusBadRequest)

	taken := h.do(http.MethodPatch, "/v1/me", second, map[string]any{"username": username})
	requireStatus(t, taken, http.StatusConflict)
	if code := errorCode(t, taken); code != "username_taken" {
		t.Errorf("code = %q, want username_taken", code)
	}

	reserved := h.do(http.MethodPatch, "/v1/me", second, map[string]any{"username": "api"})
	requireStatus(t, reserved, http.StatusConflict)
	if code := errorCode(t, reserved); code != "username_reserved" {
		t.Errorf("code = %q, want username_reserved", code)
	}

	lookup := h.do(http.MethodGet, "/v1/users/"+username, nil, nil)
	requireStatus(t, lookup, http.StatusOK)
	if _, leaked := decodeBody(t, lookup)["email"]; leaked {
		t.Error("public profile lookup must not expose email")
	}
}

func TestSecondDeviceIsPendingUntilApproved(t *testing.T) {
	// Arrange: first device is trusted, second lands pending
	h := newHarness(t)
	first := h.signUp("laptop")
	spaceID := h.createSpace(first)
	second := h.addDevice(first.UserID, "phone")

	if first.Status != store.DeviceStatusActive {
		t.Fatalf("first device status = %q, want active", first.Status)
	}
	if second.Status != store.DeviceStatusPending {
		t.Fatalf("second device status = %q, want pending", second.Status)
	}

	// Act: a pending device may authenticate but must not reach any data path
	blocked := h.do(http.MethodGet, "/v1/spaces", second, nil)
	requireStatus(t, blocked, http.StatusForbidden)
	if code := errorCode(t, blocked); code != "device_pending" {
		t.Errorf("code = %q, want device_pending", code)
	}

	selfApprove := h.do(http.MethodPost, "/v1/devices/"+second.DeviceID.String()+"/approve", second, map[string]any{"wrappedKeys": []any{}})
	requireStatus(t, selfApprove, http.StatusForbidden)
	if code := errorCode(t, selfApprove); code != "approval_required" {
		t.Errorf("code = %q, want approval_required", code)
	}

	pending := h.do(http.MethodGet, "/v1/devices/"+second.DeviceID.String()+"/pending-keys", first, nil)
	requireStatus(t, pending, http.StatusOK)
	if spaces := decodeBody(t, pending)["spaces"].([]any); len(spaces) != 1 {
		t.Fatalf("expected exactly the one space to need a wrapped key, got %d", len(spaces))
	}

	approve := h.do(http.MethodPost, "/v1/devices/"+second.DeviceID.String()+"/approve", first, map[string]any{"wrappedKeys": []map[string]any{{"spaceId": spaceID, "keyEpoch": 1, "wrappedKey": wrappedKey(t)}}})
	requireStatus(t, approve, http.StatusOK)

	// Assert: the approved device now receives the space key wrapped for it
	listed := h.do(http.MethodGet, "/v1/spaces", second, nil)
	requireStatus(t, listed, http.StatusOK)
	spaces := decodeBody(t, listed)["spaces"].([]any)
	if len(spaces) != 1 {
		t.Fatalf("expected one space, got %d", len(spaces))
	}
	if spaces[0].(map[string]any)["wrappedKey"] == nil {
		t.Error("approved device should receive its wrapped space key")
	}
}

func TestRevokedDeviceLosesAccessImmediately(t *testing.T) {
	h := newHarness(t)
	first := h.signUp("laptop")
	second := h.addDevice(first.UserID, "phone")

	revoke := h.do(http.MethodDelete, "/v1/devices/"+second.DeviceID.String(), first, nil)
	requireStatus(t, revoke, http.StatusNoContent)

	// The access token is still inside its 15 minute window, so this proves the
	// per-request device check is what enforces revocation.
	after := h.do(http.MethodGet, "/v1/me", second, nil)
	requireStatus(t, after, http.StatusUnauthorized)
}

func TestSpaceCreationRejectsPlaintextName(t *testing.T) {
	h := newHarness(t)
	a := h.signUp("laptop")

	rec := h.do(http.MethodPost, "/v1/spaces", a, map[string]any{"name": "Legal documents", "wrappedKeys": []map[string]any{{"deviceId": a.DeviceID.String(), "wrappedKey": wrappedKey(t)}}})

	// A space name has no server-side field at all; the request must not be accepted.
	requireStatus(t, rec, http.StatusBadRequest)
}

func TestSyncRelaysCiphertextVerbatim(t *testing.T) {
	// Arrange
	h := newHarness(t)
	a := h.signUp("laptop")
	spaceID := h.createSpace(a)
	payload := sealedPayload(t, seal.Buckets[0])
	cid := uuid.NewString()

	// Act
	push := h.do(http.MethodPost, "/v1/spaces/"+spaceID+"/updates", a, map[string]any{"keyEpoch": 1, "changes": []map[string]any{{"cid": cid, "ciphertext": encodeB64(payload)}}})

	// Assert
	requireStatus(t, push, http.StatusOK)
	pushed := decodeBody(t, push)
	if pushed["head"].(float64) != 1 {
		t.Fatalf("head = %v, want 1", pushed["head"])
	}

	pull := h.do(http.MethodGet, "/v1/spaces/"+spaceID+"/updates?since=0", a, nil)
	requireStatus(t, pull, http.StatusOK)
	changes := decodeBody(t, pull)["changes"].([]any)
	if len(changes) != 1 {
		t.Fatalf("expected one change, got %d", len(changes))
	}
	got := changes[0].(map[string]any)
	if got["ciphertext"] != encodeB64(payload) {
		t.Error("ciphertext was not relayed byte for byte")
	}
	if got["cid"] != cid {
		t.Errorf("cid = %v, want %s", got["cid"], cid)
	}
}

func TestSyncRetryIsIdempotent(t *testing.T) {
	h := newHarness(t)
	a := h.signUp("laptop")
	spaceID := h.createSpace(a)
	body := map[string]any{"keyEpoch": 1, "changes": []map[string]any{{"cid": uuid.NewString(), "ciphertext": encodeB64(sealedPayload(t, seal.Buckets[0]))}}}

	first := h.do(http.MethodPost, "/v1/spaces/"+spaceID+"/updates", a, body)
	second := h.do(http.MethodPost, "/v1/spaces/"+spaceID+"/updates", a, body)

	requireStatus(t, first, http.StatusOK)
	requireStatus(t, second, http.StatusOK)
	firstSeq := decodeBody(t, first)["assigned"].([]any)[0].(map[string]any)["seq"]
	secondSeq := decodeBody(t, second)["assigned"].([]any)[0].(map[string]any)["seq"]
	if firstSeq != secondSeq {
		t.Fatalf("retry produced seq %v, want the original %v", secondSeq, firstSeq)
	}
}

func TestSyncRejectsUnpaddedCiphertext(t *testing.T) {
	h := newHarness(t)
	a := h.signUp("laptop")
	spaceID := h.createSpace(a)

	rec := h.do(http.MethodPost, "/v1/spaces/"+spaceID+"/updates", a, map[string]any{"keyEpoch": 1, "changes": []map[string]any{{"cid": uuid.NewString(), "ciphertext": encodeB64(randomBytes(t, 999))}}})

	requireStatus(t, rec, http.StatusRequestEntityTooLarge)
	if code := errorCode(t, rec); code != "bucket_violation" {
		t.Errorf("code = %q, want bucket_violation", code)
	}
}

func TestSyncRejectsStaleKeyEpoch(t *testing.T) {
	h := newHarness(t)
	a := h.signUp("laptop")
	spaceID := h.createSpace(a)

	rec := h.do(http.MethodPost, "/v1/spaces/"+spaceID+"/updates", a, map[string]any{"keyEpoch": 7, "changes": []map[string]any{{"cid": uuid.NewString(), "ciphertext": encodeB64(sealedPayload(t, seal.Buckets[0]))}}})

	requireStatus(t, rec, http.StatusConflict)
	if code := errorCode(t, rec); code != "stale_epoch" {
		t.Errorf("code = %q, want stale_epoch", code)
	}
}

func TestConcurrentAppendsGetUniqueGaplessSequences(t *testing.T) {
	// Arrange
	h := newHarness(t)
	a := h.signUp("laptop")
	spaceID := h.createSpace(a)
	const writers = 20

	// Act: many devices pushing at once must never collide on a sequence number
	var wg sync.WaitGroup
	seqs := make([]float64, writers)
	codes := make([]int, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := h.do(http.MethodPost, "/v1/spaces/"+spaceID+"/updates", a, map[string]any{"keyEpoch": 1, "changes": []map[string]any{{"cid": uuid.NewString(), "ciphertext": encodeB64(sealedPayload(t, seal.Buckets[0]))}}})
			codes[i] = rec.Code
			if rec.Code == http.StatusOK {
				seqs[i] = decodeBody(t, rec)["assigned"].([]any)[0].(map[string]any)["seq"].(float64)
			}
		}(i)
	}
	wg.Wait()

	// Assert
	seen := map[float64]bool{}
	for i, code := range codes {
		if code != http.StatusOK {
			t.Fatalf("writer %d failed with status %d", i, code)
		}
		if seen[seqs[i]] {
			t.Fatalf("sequence %v was assigned twice", seqs[i])
		}
		seen[seqs[i]] = true
	}
	for n := 1.0; n <= writers; n++ {
		if !seen[n] {
			t.Errorf("sequence %v is missing — allocation left a gap", n)
		}
	}
}

func TestIdlePollReturnsNotModified(t *testing.T) {
	h := newHarness(t)
	a := h.signUp("laptop")
	spaceID := h.createSpace(a)

	first := h.do(http.MethodGet, "/v1/spaces/"+spaceID+"/updates?since=0", a, nil)
	requireStatus(t, first, http.StatusOK)
	etag := first.Header().Get("ETag")
	if etag == "" {
		t.Fatal("expected an ETag on the poll response")
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/spaces/"+spaceID+"/updates?since=0", nil)
	req.Header.Set("Authorization", "Bearer "+a.Token)
	req.Header.Set("If-None-Match", etag)
	rec := httptest.NewRecorder()
	h.server.ServeHTTP(rec, req)

	requireStatus(t, rec, http.StatusNotModified)
}

func TestSnapshotCompactionForcesResync(t *testing.T) {
	// Arrange
	h := newHarness(t)
	a := h.signUp("laptop")
	spaceID := h.createSpace(a)
	for i := 0; i < 3; i++ {
		rec := h.do(http.MethodPost, "/v1/spaces/"+spaceID+"/updates", a, map[string]any{"keyEpoch": 1, "changes": []map[string]any{{"cid": uuid.NewString(), "ciphertext": encodeB64(sealedPayload(t, seal.Buckets[0]))}}})
		requireStatus(t, rec, http.StatusOK)
	}

	// Act
	snapshot := h.do(http.MethodPost, "/v1/spaces/"+spaceID+"/snapshot", a, map[string]any{"uptoSeq": 3, "keyEpoch": 1, "ciphertext": encodeB64(sealedPayload(t, seal.Buckets[1]))})
	requireStatus(t, snapshot, http.StatusOK)

	// Assert: a client behind the compaction point is told to reload the snapshot
	behind := h.do(http.MethodGet, "/v1/spaces/"+spaceID+"/updates?since=0", a, nil)
	requireStatus(t, behind, http.StatusOK)
	body := decodeBody(t, behind)
	if body["resync"] != true {
		t.Fatalf("expected resync, got %s", behind.Body.String())
	}
	if body["snapshot"] == nil {
		t.Fatal("resync response must carry the snapshot descriptor")
	}
	if body["nextSince"].(float64) != 3 {
		t.Errorf("nextSince = %v, want 3", body["nextSince"])
	}

	stale := h.do(http.MethodPost, "/v1/spaces/"+spaceID+"/snapshot", a, map[string]any{"uptoSeq": 2, "keyEpoch": 1, "ciphertext": encodeB64(sealedPayload(t, seal.Buckets[0]))})
	requireStatus(t, stale, http.StatusConflict)
}

func TestWorkspaceDocUsesOptimisticConcurrency(t *testing.T) {
	h := newHarness(t)
	a := h.signUp("laptop")
	spaceID := h.createSpace(a)
	payload := encodeB64(sealedPayload(t, seal.Buckets[0]))

	create := h.do(http.MethodPut, "/v1/spaces/"+spaceID+"/workspace", a, map[string]any{"baseVersion": 0, "keyEpoch": 1, "ciphertext": payload})
	requireStatus(t, create, http.StatusOK)
	if decodeBody(t, create)["version"].(float64) != 1 {
		t.Fatalf("first write should produce version 1: %s", create.Body.String())
	}

	update := h.do(http.MethodPut, "/v1/spaces/"+spaceID+"/workspace", a, map[string]any{"baseVersion": 1, "keyEpoch": 1, "ciphertext": payload})
	requireStatus(t, update, http.StatusOK)

	lost := h.do(http.MethodPut, "/v1/spaces/"+spaceID+"/workspace", a, map[string]any{"baseVersion": 1, "keyEpoch": 1, "ciphertext": payload})
	requireStatus(t, lost, http.StatusConflict)
	if code := errorCode(t, lost); code != "version_conflict" {
		t.Errorf("code = %q, want version_conflict", code)
	}
}

func TestCollaborationInviteReadRemoveAndRotate(t *testing.T) {
	// Arrange
	h := newHarness(t)
	owner := h.signUp("owner")
	guest := h.signUp("guest")
	spaceID := h.createSpace(owner)

	// Act: the owner files the space key wrapped for the guest's device
	invite := h.do(http.MethodPost, "/v1/spaces/"+spaceID+"/members", owner, map[string]any{"userId": guest.UserID.String(), "role": "editor", "keyEpoch": 1, "wrappedKeys": []map[string]any{{"deviceId": guest.DeviceID.String(), "wrappedKey": wrappedKey(t)}}})
	requireStatus(t, invite, http.StatusCreated)

	// Assert: the guest sees the space and receives their wrapped key
	listed := h.do(http.MethodGet, "/v1/spaces", guest, nil)
	requireStatus(t, listed, http.StatusOK)
	spaces := decodeBody(t, listed)["spaces"].([]any)
	if len(spaces) != 1 || spaces[0].(map[string]any)["wrappedKey"] == nil {
		t.Fatalf("guest should see the space with a wrapped key: %s", listed.Body.String())
	}

	directory := h.do(http.MethodGet, "/v1/keys/"+guest.UserID.String(), owner, nil)
	requireStatus(t, directory, http.StatusOK)
	if devices := decodeBody(t, directory)["devices"].([]any); len(devices) != 1 {
		t.Fatalf("key directory should list the guest's active device, got %d", len(devices))
	}

	guestWrite := h.do(http.MethodPost, "/v1/spaces/"+spaceID+"/updates", guest, map[string]any{"keyEpoch": 1, "changes": []map[string]any{{"cid": uuid.NewString(), "ciphertext": encodeB64(sealedPayload(t, seal.Buckets[0]))}}})
	requireStatus(t, guestWrite, http.StatusOK)

	remove := h.do(http.MethodDelete, "/v1/spaces/"+spaceID+"/members/"+guest.UserID.String(), owner, nil)
	requireStatus(t, remove, http.StatusNoContent)

	afterRemoval := h.do(http.MethodGet, "/v1/spaces/"+spaceID+"/updates?since=0", guest, nil)
	requireStatus(t, afterRemoval, http.StatusNotFound)

	// Rotation must cover every remaining member device or be refused wholesale
	incomplete := h.do(http.MethodPost, "/v1/spaces/"+spaceID+"/keys", owner, map[string]any{"newEpoch": 2, "wrappedKeys": []map[string]any{{"userId": guest.UserID.String(), "deviceId": guest.DeviceID.String(), "wrappedKey": wrappedKey(t)}}})
	requireStatus(t, incomplete, http.StatusConflict)
	if code := errorCode(t, incomplete); code != "epoch_conflict" {
		t.Errorf("code = %q, want epoch_conflict", code)
	}

	rotate := h.do(http.MethodPost, "/v1/spaces/"+spaceID+"/keys", owner, map[string]any{"newEpoch": 2, "wrappedKeys": []map[string]any{{"userId": owner.UserID.String(), "deviceId": owner.DeviceID.String(), "wrappedKey": wrappedKey(t)}}})
	requireStatus(t, rotate, http.StatusOK)

	stale := h.do(http.MethodPost, "/v1/spaces/"+spaceID+"/updates", owner, map[string]any{"keyEpoch": 1, "changes": []map[string]any{{"cid": uuid.NewString(), "ciphertext": encodeB64(sealedPayload(t, seal.Buckets[0]))}}})
	requireStatus(t, stale, http.StatusConflict)
	if code := errorCode(t, stale); code != "stale_epoch" {
		t.Errorf("post-rotation write code = %q, want stale_epoch", code)
	}
}

func TestNonMemberCannotReachSpace(t *testing.T) {
	h := newHarness(t)
	owner := h.signUp("owner")
	stranger := h.signUp("stranger")
	spaceID := h.createSpace(owner)

	rec := h.do(http.MethodGet, "/v1/spaces/"+spaceID+"/updates?since=0", stranger, nil)

	// Not-a-member is reported as not-found so space ids cannot be probed.
	requireStatus(t, rec, http.StatusNotFound)
}

func TestViewerCannotWrite(t *testing.T) {
	h := newHarness(t)
	owner := h.signUp("owner")
	viewer := h.signUp("viewer")
	spaceID := h.createSpace(owner)

	invite := h.do(http.MethodPost, "/v1/spaces/"+spaceID+"/members", owner, map[string]any{"userId": viewer.UserID.String(), "role": "viewer", "keyEpoch": 1, "wrappedKeys": []map[string]any{{"deviceId": viewer.DeviceID.String(), "wrappedKey": wrappedKey(t)}}})
	requireStatus(t, invite, http.StatusCreated)

	read := h.do(http.MethodGet, "/v1/spaces/"+spaceID+"/updates?since=0", viewer, nil)
	requireStatus(t, read, http.StatusOK)

	write := h.do(http.MethodPost, "/v1/spaces/"+spaceID+"/updates", viewer, map[string]any{"keyEpoch": 1, "changes": []map[string]any{{"cid": uuid.NewString(), "ciphertext": encodeB64(sealedPayload(t, seal.Buckets[0]))}}})
	requireStatus(t, write, http.StatusForbidden)
}

func TestPublishRequiresUsername(t *testing.T) {
	h := newHarness(t)
	a := h.signUp("laptop")

	rec := h.do(http.MethodPost, "/v1/publish", a, map[string]any{"slug": "reading-list", "html": encodeB64([]byte("<h1>hi</h1>")), "blocks": encodeB64([]byte(`{"blocks":[]}`)), "assetUrls": []string{}, "ogTitle": "Reading list", "ogDescription": ""})

	// Without object storage configured the route reports unavailable; with it
	// configured but no @handle set, it reports the missing username.
	if rec.Code != http.StatusServiceUnavailable && rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 503 (no blob store) or 400 (no username); body = %s", rec.Code, rec.Body.String())
	}
}

func TestRefreshRotationDetectsReuse(t *testing.T) {
	// Arrange
	h := newHarness(t)
	a := h.signUp("laptop")
	issued, err := h.store.IssueRefreshToken(context.Background(), a.UserID, a.DeviceID, "web", nil)
	if err != nil {
		t.Fatalf("issue refresh token: %v", err)
	}

	// Act
	first := h.do(http.MethodPost, "/v1/auth/refresh", nil, map[string]any{"refreshToken": issued.Plaintext})
	requireStatus(t, first, http.StatusOK)
	rotated := decodeBody(t, first)["refreshToken"].(string)

	// Age the spent token past the retry grace so the replay reads as theft
	// rather than as a client that never saw the response.
	if _, err := h.store.Pool().Exec(context.Background(), "UPDATE refresh_tokens SET used_at = now() - interval '1 hour' WHERE family_id = $1 AND used_at IS NOT NULL", issued.FamilyID); err != nil {
		t.Fatalf("age spent token: %v", err)
	}
	replay := h.do(http.MethodPost, "/v1/auth/refresh", nil, map[string]any{"refreshToken": issued.Plaintext})

	// Assert: replay is detected and the whole family dies with it
	requireStatus(t, replay, http.StatusUnauthorized)
	if code := errorCode(t, replay); code != "token_reused" {
		t.Errorf("code = %q, want token_reused", code)
	}
	afterFamilyRevoked := h.do(http.MethodPost, "/v1/auth/refresh", nil, map[string]any{"refreshToken": rotated})
	requireStatus(t, afterFamilyRevoked, http.StatusUnauthorized)
}

func TestRefreshRotationForgivesRetryWithinGrace(t *testing.T) {
	// Arrange: a client whose rotation response was lost still holds the token
	// the server has already spent, and retries with it.
	h := newHarness(t)
	a := h.signUp("phone")
	issued, err := h.store.IssueRefreshToken(context.Background(), a.UserID, a.DeviceID, "ios", nil)
	if err != nil {
		t.Fatalf("issue refresh token: %v", err)
	}
	requireStatus(t, h.do(http.MethodPost, "/v1/auth/refresh", nil, map[string]any{"refreshToken": issued.Plaintext}), http.StatusOK)

	// Act
	retry := h.do(http.MethodPost, "/v1/auth/refresh", nil, map[string]any{"refreshToken": issued.Plaintext})

	// Assert: the session survives and the retry gets a usable token
	requireStatus(t, retry, http.StatusOK)
	next, _ := decodeBody(t, retry)["refreshToken"].(string)
	if next == "" {
		t.Fatal("retry within grace returned no refresh token")
	}
	requireStatus(t, h.do(http.MethodPost, "/v1/auth/refresh", nil, map[string]any{"refreshToken": next}), http.StatusOK)
}

func TestRefreshTTLDependsOnPlatform(t *testing.T) {
	// Arrange
	h := newHarness(t)
	a := h.signUp("laptop")

	// Act
	web, err := h.store.IssueRefreshToken(context.Background(), a.UserID, a.DeviceID, "web", nil)
	if err != nil {
		t.Fatalf("issue web token: %v", err)
	}
	app, err := h.store.IssueRefreshToken(context.Background(), a.UserID, a.DeviceID, "ios", nil)
	if err != nil {
		t.Fatalf("issue app token: %v", err)
	}

	// Assert
	if got := time.Until(web.ExpiresAt); got > store.RefreshTTLWeb || got < store.RefreshTTLWeb-time.Minute {
		t.Errorf("web ttl = %v, want ~%v", got, store.RefreshTTLWeb)
	}
	if got := time.Until(app.ExpiresAt); got > store.RefreshTTLApp || got < store.RefreshTTLApp-time.Minute {
		t.Errorf("app ttl = %v, want ~%v", got, store.RefreshTTLApp)
	}
}

func TestUnauthenticatedRequestsAreRejected(t *testing.T) {
	h := newHarness(t)

	for _, path := range []string{"/v1/me", "/v1/spaces", "/v1/devices"} {
		rec := h.do(http.MethodGet, path, nil, nil)
		requireStatus(t, rec, http.StatusUnauthorized)
	}
}

// TestEscrowWrapsNeverLeaveTheServer pins the property that makes escrow
// tolerable at all. The account's copy of a household key is readable by the
// server — that is the deal — but it must never be servable to a caller, or a
// pending device would be handed the very thing the email code is supposed to
// gate. The endpoint that used to serve them, back when the copy was sealed to
// a phrase only the person held, is gone.
func TestEscrowWrapsNeverLeaveTheServer(t *testing.T) {
	// Arrange
	h := newHarness(t)
	owner := h.signUp("owner")
	h.escrowPublicKey(t, owner.UserID)
	spaceID := h.createSpaceWithEscrow(owner)

	pending := h.addDevice(owner.UserID, "a laptop nobody has let in")
	if pending.Status != "pending" {
		t.Fatalf("second device status = %q, want pending", pending.Status)
	}

	// Act — the removed route, and the query that used to smuggle the same bytes
	// out through the ordinary spaces list.
	removed := h.do(http.MethodGet, "/v1/recovery/spaces", pending, nil)
	viaQuery := h.do(http.MethodGet, "/v1/spaces?includeRecoveryKeys=true", owner, nil)
	spaces := h.do(http.MethodGet, "/v1/spaces", pending, nil)

	// Assert — no route serves the escrow copy, and the ordinary list is still
	// behind device approval.
	requireStatus(t, removed, http.StatusNotFound)
	requireStatus(t, spaces, http.StatusForbidden)

	requireStatus(t, viaQuery, http.StatusOK)
	for _, raw := range decodeBody(t, viaQuery)["spaces"].([]any) {
		if _, leaked := raw.(map[string]any)["recoveryWrappedKey"]; leaked {
			t.Fatal("GET /spaces still serves the account escrow wrap")
		}
	}

	// The wrap does exist; it is simply the server's to hold.
	var escrowWraps int
	if err := h.store.Pool().QueryRow(context.Background(), "SELECT count(*) FROM space_keys WHERE space_id = $1 AND device_id IS NULL", spaceID).Scan(&escrowWraps); err != nil {
		t.Fatalf("count escrow wraps: %v", err)
	}
	if escrowWraps != 1 {
		t.Fatalf("escrow wraps = %d, want 1", escrowWraps)
	}
}

// createSpaceWithEscrow creates a space whose key is wrapped for the actor's
// device and for their account escrow key.
func (h *harness) createSpaceWithEscrow(a *actor) string {
	h.t.Helper()
	body := map[string]any{"wrappedKeys": []map[string]any{
		{"deviceId": a.DeviceID.String(), "wrappedKey": wrappedKey(h.t)},
		{"wrappedKey": wrappedKey(h.t)},
	}}
	rec := h.do(http.MethodPost, "/v1/spaces", a, body)
	requireStatus(h.t, rec, http.StatusCreated)
	return decodeBody(h.t, rec)["id"].(string)
}

// TestApproveStillAcceptsTheFieldsDeployedClientsSend is a contract test, not a
// feature test. decodeJSON refuses unknown fields, so deleting a field from a
// request struct is a breaking API change for every client already in the wild —
// which is exactly how device approval started answering 400 in production after
// the recovery phrase was removed. Any future removal has to fail here first.
func TestApproveStillAcceptsTheFieldsDeployedClientsSend(t *testing.T) {
	// Arrange — an active device approving a pending one, as the notes app does.
	h := newHarness(t)
	owner := h.signUp("an already trusted laptop")
	pending := h.addDevice(owner.UserID, "a new browser")

	// Act — the exact body shape a deployed client sends, legacy field included.
	rec := h.do(http.MethodPost, "/v1/devices/"+pending.DeviceID.String()+"/approve", owner, map[string]any{
		"recovery": false,
		"wrappedKeys": []map[string]any{
			{"spaceId": uuid.NewString(), "keyEpoch": 1, "wrappedKey": wrappedKey(t)},
		},
	})

	// Assert
	requireStatus(t, rec, http.StatusOK)
	if decodeBody(t, rec)["status"] != "active" {
		t.Fatalf("the device was not approved: %s", rec.Body.String())
	}
}
