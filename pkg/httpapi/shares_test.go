package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

// sharePayload builds a body shaped like the client's sealed container: the
// "OSA1" magic followed by noise.
func sharePayload(t *testing.T, n int) []byte {
	t.Helper()
	return append([]byte("OSA1"), randomBytes(t, n)...)
}

// putShare uploads raw bytes, which the JSON-only harness helper cannot do.
func (h *harness) putShare(a *actor, spaceID, shareID string, body []byte) *httptest.ResponseRecorder {
	h.t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/v1/spaces/"+spaceID+"/shares/"+shareID, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Authorization", "Bearer "+a.Token)
	rec := httptest.NewRecorder()
	h.server.ServeHTTP(rec, req)
	return rec
}

func TestSharePublishesThenReadsBackPublicly(t *testing.T) {
	h := newHarness(t)
	owner := h.signUp("owner")
	spaceID := h.createSpace(owner)
	shareID := uuid.NewString()
	sealed := sharePayload(t, 512)

	requireStatus(t, h.putShare(owner, spaceID, shareID, sealed), http.StatusOK)
	rec := h.do(http.MethodGet, "/v1/shares/"+shareID, nil, nil)

	requireStatus(t, rec, http.StatusOK)
	if !bytes.Equal(rec.Body.Bytes(), sealed) {
		t.Errorf("public read returned %d bytes, want the %d uploaded", rec.Body.Len(), len(sealed))
	}
}

// Republishing must overwrite in place, or the link a reader already holds would
// stop resolving every time the author edited the page.
func TestShareRepublishReplacesBytesAtTheSameLink(t *testing.T) {
	h := newHarness(t)
	owner := h.signUp("owner")
	spaceID := h.createSpace(owner)
	shareID := uuid.NewString()
	updated := sharePayload(t, 700)

	requireStatus(t, h.putShare(owner, spaceID, shareID, sharePayload(t, 300)), http.StatusOK)
	requireStatus(t, h.putShare(owner, spaceID, shareID, updated), http.StatusOK)

	rec := h.do(http.MethodGet, "/v1/shares/"+shareID, nil, nil)
	requireStatus(t, rec, http.StatusOK)
	if !bytes.Equal(rec.Body.Bytes(), updated) {
		t.Error("the public read did not return the republished bytes")
	}
}

// Revoking is the real guarantee the feature makes, so it has to actually stop
// serving the ciphertext.
func TestRevokedShareStopsResolving(t *testing.T) {
	h := newHarness(t)
	owner := h.signUp("owner")
	spaceID := h.createSpace(owner)
	shareID := uuid.NewString()

	requireStatus(t, h.putShare(owner, spaceID, shareID, sharePayload(t, 256)), http.StatusOK)
	requireStatus(t, h.do(http.MethodDelete, "/v1/spaces/"+spaceID+"/shares/"+shareID, owner, nil), http.StatusNoContent)

	requireStatus(t, h.do(http.MethodGet, "/v1/shares/"+shareID, nil, nil), http.StatusNotFound)
}

// A share id is the capability in the link. Letting a second space write to one
// it does not own would let anyone holding a link overwrite what it serves.
func TestShareIdCannotBeReboundByAnotherSpace(t *testing.T) {
	h := newHarness(t)
	owner := h.signUp("owner")
	stranger := h.signUp("stranger")
	shareID := uuid.NewString()

	requireStatus(t, h.putShare(owner, h.createSpace(owner), shareID, sharePayload(t, 256)), http.StatusOK)
	rec := h.putShare(stranger, h.createSpace(stranger), shareID, sharePayload(t, 256))

	requireStatus(t, rec, http.StatusForbidden)
	if code := errorCode(t, rec); code != "share_forbidden" {
		t.Errorf("error code = %q, want share_forbidden", code)
	}
}

func TestShareRejectsOversizedAndMalformedBodies(t *testing.T) {
	h := newHarness(t)
	owner := h.signUp("owner")
	spaceID := h.createSpace(owner)

	oversized := h.putShare(owner, spaceID, uuid.NewString(), sharePayload(t, maxShareBody+1))
	requireStatus(t, oversized, http.StatusRequestEntityTooLarge)

	malformed := h.putShare(owner, spaceID, uuid.NewString(), randomBytes(t, 64))
	requireStatus(t, malformed, http.StatusBadRequest)
}

// A reader holds only the link, so the public route must not require a session —
// and must not leak which space the ciphertext came from.
func TestPublicShareReadNeedsNoSessionAndLeaksNoSpace(t *testing.T) {
	h := newHarness(t)
	owner := h.signUp("owner")
	spaceID := h.createSpace(owner)
	shareID := uuid.NewString()
	requireStatus(t, h.putShare(owner, spaceID, shareID, sharePayload(t, 256)), http.StatusOK)

	rec := h.do(http.MethodGet, "/v1/shares/"+shareID, nil, nil)

	requireStatus(t, rec, http.StatusOK)
	for name, value := range rec.Header() {
		for _, v := range value {
			if bytes.Contains([]byte(v), []byte(spaceID)) {
				t.Errorf("header %s leaked the space id", name)
			}
		}
	}
}

func TestUnknownShareIsNotFound(t *testing.T) {
	h := newHarness(t)

	requireStatus(t, h.do(http.MethodGet, "/v1/shares/"+uuid.NewString(), nil, nil), http.StatusNotFound)
	requireStatus(t, h.do(http.MethodGet, "/v1/shares/not-a-uuid", nil, nil), http.StatusNotFound)
}
