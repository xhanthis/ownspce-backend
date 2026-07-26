package httpapi

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/ownspce/backend/internal/blob"
	"github.com/ownspce/backend/internal/seal"
	"github.com/ownspce/backend/internal/store"
)

type postUpdatesRequest struct {
	KeyEpoch int `json:"keyEpoch"`
	Changes  []struct {
		CID        string `json:"cid"`
		Ciphertext string `json:"ciphertext"`
	} `json:"changes"`
}

// handlePostUpdates appends sealed change-sets to a space's log and returns the
// sequence number assigned to each. The payloads are opaque: the only thing
// checked is that each ciphertext length is a padding bucket, which is what stops
// stored sizes from leaking note lengths.
// Handles: stale key epoch after a rotation (409 stale_epoch), retried batches
// (idempotent by client change id), unpadded ciphertext (413 bucket_violation).
func (s *Server) handlePostUpdates(w http.ResponseWriter, r *http.Request) {
	spaceID, err := parseUUIDParam(chi.URLParam(r, "spaceID"), "spaceId")
	if err != nil {
		writeError(w, err)
		return
	}

	var req postUpdatesRequest
	if err := decodeJSON(w, r, maxSyncBody, &req); err != nil {
		writeError(w, err)
		return
	}
	if req.KeyEpoch <= 0 {
		writeError(w, badRequest("keyEpoch is required"))
		return
	}
	if len(req.Changes) > store.MaxChangesPerBatch {
		writeError(w, badRequest("a batch may carry at most %d changes", store.MaxChangesPerBatch))
		return
	}

	changes := make([]store.PendingChange, 0, len(req.Changes))
	for i, c := range req.Changes {
		cid, err := uuid.Parse(c.CID)
		if err != nil {
			writeError(w, badRequest("changes[%d].cid must be a uuid", i))
			return
		}
		ciphertext, err := decodeB64(c.Ciphertext, "changes[].ciphertext")
		if err != nil {
			writeError(w, err)
			return
		}
		if _, err := seal.ValidateCiphertext(ciphertext); err != nil {
			writeError(w, errTooLarge("bucket_violation", fmt.Sprintf("changes[%d]: %v", i, err)))
			return
		}
		changes = append(changes, store.PendingChange{CID: cid, Ciphertext: ciphertext})
	}

	assigned, head, err := s.store.AppendChanges(r.Context(), spaceID, req.KeyEpoch, callerFrom(r.Context()).DeviceID, changes)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrConflict):
			writeError(w, errConflict("stale_epoch", "the space key has rotated; fetch your new wrapped key, re-encrypt, and retry"))
		case errors.Is(err, store.ErrNotFound):
			writeError(w, errNotFound("space not found"))
		default:
			writeError(w, err)
		}
		return
	}

	out := make([]map[string]any, 0, len(assigned))
	for _, a := range assigned {
		out = append(out, map[string]any{"cid": a.CID.String(), "seq": a.Seq})
	}
	writeJSON(w, http.StatusOK, map[string]any{"assigned": out, "head": head})
}

// handleGetUpdates is the catch-up poll clients run every 1-2 seconds while active.
// It answers from a single indexed read when the caller is already at head, and
// supports ETag so an idle poll costs a 304.
// Handles: cursor older than the compaction point (resync with the snapshot
// descriptor), paging via nextSince.
func (s *Server) handleGetUpdates(w http.ResponseWriter, r *http.Request) {
	spaceID, err := parseUUIDParam(chi.URLParam(r, "spaceID"), "spaceId")
	if err != nil {
		writeError(w, err)
		return
	}
	since, err := parseSince(r.URL.Query().Get("since"))
	if err != nil {
		writeError(w, err)
		return
	}
	limit := 0
	if raw := r.URL.Query().Get("limit"); raw != "" {
		limit, _ = strconv.Atoi(raw)
	}

	page, err := s.store.GetChanges(r.Context(), spaceID, since, limit)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, errNotFound("space not found"))
			return
		}
		writeError(w, err)
		return
	}

	etag := fmt.Sprintf(`"%d-%d"`, page.Head, page.WorkspaceVersion)
	w.Header().Set("ETag", etag)
	if len(page.Changes) == 0 && !page.NeedsResync && r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	resp := map[string]any{"head": page.Head, "oldestSeq": page.OldestSeq, "keyEpoch": page.KeyEpoch, "workspaceVersion": page.WorkspaceVersion, "resync": page.NeedsResync, "changes": []any{}, "nextSince": since}

	if page.NeedsResync {
		snapshot, snapErr := s.store.GetSnapshot(r.Context(), spaceID)
		if snapErr != nil && !errors.Is(snapErr, store.ErrNotFound) {
			writeError(w, snapErr)
			return
		}
		if snapshot != nil {
			resp["snapshot"] = snapshotPayload(snapshot)
			resp["nextSince"] = snapshot.UptoSeq
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}

	changes := make([]map[string]any, 0, len(page.Changes))
	nextSince := since
	for _, c := range page.Changes {
		changes = append(changes, map[string]any{"seq": c.Seq, "cid": c.CID.String(), "keyEpoch": c.KeyEpoch, "authorDeviceId": c.AuthorDeviceID.String(), "ciphertext": encodeB64(c.Ciphertext), "createdAt": c.CreatedAt.UTC().Format(time.RFC3339)})
		nextSince = c.Seq
	}
	if len(changes) == 0 {
		nextSince = page.Head
	}
	resp["changes"] = changes
	resp["nextSince"] = nextSince
	writeJSON(w, http.StatusOK, resp)
}

func snapshotPayload(snap *store.Snapshot) map[string]any {
	return map[string]any{"uptoSeq": snap.UptoSeq, "keyEpoch": snap.KeyEpoch, "storage": snap.Storage, "ciphertext": nilIfEmpty(encodeB64(snap.Ciphertext)), "blobUrl": snap.BlobURL, "sizeBucket": snap.SizeBucket, "createdAt": snap.CreatedAt.UTC().Format(time.RFC3339)}
}

type postSnapshotRequest struct {
	UptoSeq    int64  `json:"uptoSeq"`
	KeyEpoch   int    `json:"keyEpoch"`
	Ciphertext string `json:"ciphertext"`
	BlobURL    string `json:"blobUrl"`
	SizeBucket int    `json:"sizeBucket"`
}

// handlePostSnapshot commits a compacted snapshot and truncates the log up to
// uptoSeq. Small snapshots arrive inline; larger ones are uploaded first via
// PUT /snapshot/blob and committed here by reference.
// Handles: snapshot behind the stored one or ahead of head (409), stale epoch (409),
// blob URLs not issued by this API (rejected).
func (s *Server) handlePostSnapshot(w http.ResponseWriter, r *http.Request) {
	spaceID, err := parseUUIDParam(chi.URLParam(r, "spaceID"), "spaceId")
	if err != nil {
		writeError(w, err)
		return
	}

	var req postSnapshotRequest
	if err := decodeJSON(w, r, maxSnapshotBody, &req); err != nil {
		writeError(w, err)
		return
	}
	if req.KeyEpoch <= 0 {
		writeError(w, badRequest("keyEpoch is required"))
		return
	}
	if req.UptoSeq < 0 {
		writeError(w, badRequest("uptoSeq must not be negative"))
		return
	}
	if (req.Ciphertext == "") == (req.BlobURL == "") {
		writeError(w, badRequest("supply exactly one of ciphertext (inline) or blobUrl (uploaded)"))
		return
	}

	var (
		storage    = "inline"
		ciphertext []byte
		blobURL    *string
		sizeBucket = req.SizeBucket
	)
	if req.Ciphertext != "" {
		ciphertext, err = decodeB64(req.Ciphertext, "ciphertext")
		if err != nil {
			writeError(w, err)
			return
		}
		bucket, err := seal.ValidateCiphertext(ciphertext)
		if err != nil {
			writeError(w, errTooLarge("bucket_violation", err.Error()))
			return
		}
		sizeBucket = bucket
	} else {
		if !isOwnBlobURL(req.BlobURL) {
			writeError(w, badRequest("blobUrl must be a URL returned by PUT /snapshot/blob"))
			return
		}
		storage = "blob"
		blobURL = &req.BlobURL
		if sizeBucket <= 0 {
			writeError(w, badRequest("sizeBucket is required for a blob snapshot"))
			return
		}
	}

	c := callerFrom(r.Context())
	staleBlob, err := s.store.PutSnapshot(r.Context(), spaceID, c.DeviceID, req.UptoSeq, req.KeyEpoch, storage, ciphertext, blobURL, sizeBucket)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrConflict):
			writeError(w, errConflict("snapshot_conflict", "the snapshot is behind the stored one, ahead of head, or built under a rotated key"))
		case errors.Is(err, store.ErrNotFound):
			writeError(w, errNotFound("space not found"))
		default:
			writeError(w, err)
		}
		return
	}

	if staleBlob != nil {
		go func(url string) {
			if err := s.blob.Delete(detachedContext(), []string{url}); err != nil {
				log.Printf("delete superseded snapshot blob: %v", err)
			}
		}(*staleBlob)
	}
	writeJSON(w, http.StatusOK, map[string]any{"uptoSeq": req.UptoSeq, "keyEpoch": req.KeyEpoch, "storage": storage, "oldestSeq": req.UptoSeq + 1})
}

// handleUploadSnapshotBlob accepts a raw ciphertext body and stores it in Vercel
// Blob under a random path, returning the URL to commit with POST /snapshot.
// Uploading through the API (rather than handing out a client upload token) keeps
// object creation authorized by space role.
func (s *Server) handleUploadSnapshotBlob(w http.ResponseWriter, r *http.Request) {
	if !s.blob.Configured() {
		writeError(w, errUnavailable("object storage is not configured; use an inline snapshot"))
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxSnapshotBody)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeError(w, errTooLarge("payload_too_large", "snapshot exceeds the upload limit"))
			return
		}
		writeError(w, err)
		return
	}

	bucket, err := seal.ValidateCiphertext(body)
	if err != nil {
		writeError(w, errTooLarge("bucket_violation", err.Error()))
		return
	}

	url, err := s.blob.Put(r.Context(), blob.RandomPath("snapshots", ".bin"), "application/octet-stream", body, 0)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"blobUrl": url, "sizeBucket": bucket})
}

func (s *Server) handleGetSnapshot(w http.ResponseWriter, r *http.Request) {
	spaceID, err := parseUUIDParam(chi.URLParam(r, "spaceID"), "spaceId")
	if err != nil {
		writeError(w, err)
		return
	}

	snapshot, err := s.store.GetSnapshot(r.Context(), spaceID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, errNotFound("this space has no snapshot yet"))
			return
		}
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, snapshotPayload(snapshot))
}

func (s *Server) handleGetWorkspace(w http.ResponseWriter, r *http.Request) {
	spaceID, err := parseUUIDParam(chi.URLParam(r, "spaceID"), "spaceId")
	if err != nil {
		writeError(w, err)
		return
	}

	doc, err := s.store.GetWorkspaceDoc(r.Context(), spaceID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeJSON(w, http.StatusOK, map[string]any{"version": 0, "keyEpoch": 0, "ciphertext": nil})
			return
		}
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": doc.Version, "keyEpoch": doc.KeyEpoch, "ciphertext": encodeB64(doc.Ciphertext), "updatedAt": doc.UpdatedAt.UTC().Format(time.RFC3339)})
}

type putWorkspaceRequest struct {
	BaseVersion int64  `json:"baseVersion"`
	KeyEpoch    int    `json:"keyEpoch"`
	Ciphertext  string `json:"ciphertext"`
}

// handlePutWorkspace replaces the sealed Tier 1 document (page tree, titles, tags,
// pins) under optimistic concurrency: a mismatched baseVersion returns 409 and the
// client merges locally before retrying, because the server cannot merge what it
// cannot read.
func (s *Server) handlePutWorkspace(w http.ResponseWriter, r *http.Request) {
	spaceID, err := parseUUIDParam(chi.URLParam(r, "spaceID"), "spaceId")
	if err != nil {
		writeError(w, err)
		return
	}

	var req putWorkspaceRequest
	if err := decodeJSON(w, r, maxSyncBody, &req); err != nil {
		writeError(w, err)
		return
	}
	if req.KeyEpoch <= 0 {
		writeError(w, badRequest("keyEpoch is required"))
		return
	}
	if req.BaseVersion < 0 {
		writeError(w, badRequest("baseVersion must not be negative"))
		return
	}

	ciphertext, err := decodeB64(req.Ciphertext, "ciphertext")
	if err != nil {
		writeError(w, err)
		return
	}
	if _, err := seal.ValidateCiphertext(ciphertext); err != nil {
		writeError(w, errTooLarge("bucket_violation", err.Error()))
		return
	}

	version, err := s.store.PutWorkspaceDoc(r.Context(), spaceID, callerFrom(r.Context()).DeviceID, req.BaseVersion, req.KeyEpoch, ciphertext)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrConflict):
			writeError(w, errConflict("version_conflict", "the workspace document changed since baseVersion, or the space key rotated; refetch, merge locally, and retry"))
		case errors.Is(err, store.ErrNotFound):
			writeError(w, errNotFound("space not found"))
		default:
			writeError(w, err)
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": version})
}
