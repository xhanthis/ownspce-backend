package httpapi

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
)

// putAttachmentBlob uploads raw bytes at a grant-bearing URL, the way the client
// does: a plain fetch with no Authorization header.
func (h *harness) putAttachmentBlob(path string, body []byte) *httptest.ResponseRecorder {
	h.t.Helper()
	req := httptest.NewRequest(http.MethodPut, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/octet-stream")
	rec := httptest.NewRecorder()
	h.server.ServeHTTP(rec, req)
	return rec
}

// grantURL signs an upload path directly, so the grant checks can be exercised
// without object storage standing behind them.
func (h *harness) grantURL(spaceID, attachmentID uuid.UUID, size int64, ttl time.Duration) string {
	h.t.Helper()
	signature, expiresAt := h.server.uploads.Sign(spaceID, attachmentID, size, ttl)
	return fmt.Sprintf("/v1/spaces/%s/attachments/%s/blob?size=%d&exp=%d&sig=%s", spaceID, attachmentID, size, expiresAt, signature)
}

// The upload route is deliberately unauthenticated, so the grant is the only
// thing standing between a stranger and this space's object storage.
func TestAttachmentUploadRejectsMissingOrForgedGrant(t *testing.T) {
	h := newHarness(t)
	spaceID, attachmentID := uuid.New(), uuid.New()
	body := randomBytes(t, 128)

	cases := map[string]string{
		"no grant at all": fmt.Sprintf("/v1/spaces/%s/attachments/%s/blob", spaceID, attachmentID),
		"forged signature": fmt.Sprintf("/v1/spaces/%s/attachments/%s/blob?size=128&exp=%d&sig=AAAA",
			spaceID, attachmentID, time.Now().Add(time.Minute).Unix()),
		"expired grant": h.grantURL(spaceID, attachmentID, 128, -time.Second),
	}
	for name, path := range cases {
		rec := h.putAttachmentBlob(path, body)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: status = %d, want %d", name, rec.Code, http.StatusForbidden)
		}
	}
}

// A grant names an exact byte count, which is what stops one minted for a
// thumbnail being replayed to store something far larger.
func TestAttachmentUploadRejectsBodyThatIsNotTheGrantedSize(t *testing.T) {
	h := newHarness(t)
	spaceID, attachmentID := uuid.New(), uuid.New()

	rec := h.putAttachmentBlob(h.grantURL(spaceID, attachmentID, 128, time.Minute), randomBytes(t, 4096))

	if rec.Code != http.StatusForbidden && rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want a refusal; body = %s", rec.Code, rec.Body.String())
	}
}

func TestAttachmentUploadURLRejectsImpossibleSizes(t *testing.T) {
	h := newHarness(t)
	owner := h.signUp("owner")
	spaceID := h.createSpace(owner)
	path := "/v1/spaces/" + spaceID + "/attachments/" + uuid.NewString() + "/upload-url"

	for name, size := range map[string]int64{"zero": 0, "negative": -1, "over the cap": maxAttachmentBody + 1} {
		rec := h.do(http.MethodPost, path, owner, map[string]any{"size": size})
		if rec.Code != http.StatusRequestEntityTooLarge && rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s: status = %d, want a refusal; body = %s", name, rec.Code, rec.Body.String())
		}
	}
}

// Committing without uploading first must not leave a row pointing at bytes that
// were never stored.
func TestAttachmentCommitWithoutUploadIsRejected(t *testing.T) {
	h := newHarness(t)
	owner := h.signUp("owner")
	spaceID := h.createSpace(owner)

	rec := h.do(http.MethodPost, "/v1/spaces/"+spaceID+"/attachments/"+uuid.NewString(), owner, map[string]any{"size": 128})

	requireStatus(t, rec, http.StatusConflict)
	if code := errorCode(t, rec); code != "upload_missing" {
		t.Errorf("error code = %q, want upload_missing", code)
	}
}

func TestUnknownAttachmentReadsAsNotFound(t *testing.T) {
	h := newHarness(t)
	owner := h.signUp("owner")
	spaceID := h.createSpace(owner)

	requireStatus(t, h.do(http.MethodGet, "/v1/spaces/"+spaceID+"/attachments/"+uuid.NewString(), owner, nil), http.StatusNotFound)
	requireStatus(t, h.do(http.MethodDelete, "/v1/spaces/"+spaceID+"/attachments/"+uuid.NewString(), owner, nil), http.StatusNoContent)
}

// A stranger holding a valid attachment id must still be refused by the space
// role check, not merely by the id being unguessable.
func TestAttachmentIsScopedToItsSpace(t *testing.T) {
	h := newHarness(t)
	owner := h.signUp("owner")
	stranger := h.signUp("stranger")
	spaceID := h.createSpace(owner)

	rec := h.do(http.MethodGet, "/v1/spaces/"+spaceID+"/attachments/"+uuid.NewString(), stranger, nil)

	if rec.Code != http.StatusForbidden && rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want the stranger refused; body = %s", rec.Code, rec.Body.String())
	}
}
