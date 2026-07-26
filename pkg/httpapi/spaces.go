package httpapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/ownspce/backend/pkg/seal"
	"github.com/ownspce/backend/pkg/store"
)

type wrappedKeyInput struct {
	DeviceID   *string `json:"deviceId"`
	UserID     *string `json:"userId"`
	WrappedKey string  `json:"wrappedKey"`
}

// parseWrappedKeys validates a batch of wrapped keys. A nil deviceId means the
// key is wrapped to the account recovery key, which is what makes recovery-phrase
// restore possible without the server ever holding an unwrapped key.
func parseWrappedKeys(inputs []wrappedKeyInput) ([]store.DeviceWrappedKey, error) {
	out := make([]store.DeviceWrappedKey, 0, len(inputs))
	for i, in := range inputs {
		wrapped, err := decodeB64(in.WrappedKey, "wrappedKeys[].wrappedKey")
		if err != nil {
			return nil, err
		}
		if err := seal.ValidateWrappedKey(wrapped); err != nil {
			return nil, badRequest("wrappedKeys[%d]: %v", i, err)
		}

		key := store.DeviceWrappedKey{WrappedKey: wrapped}
		if in.DeviceID != nil {
			deviceID, err := parseUUIDParam(*in.DeviceID, "wrappedKeys[].deviceId")
			if err != nil {
				return nil, err
			}
			key.DeviceID = &deviceID
		}
		out = append(out, key)
	}
	return out, nil
}

type createSpaceRequest struct {
	WrappedKeys []wrappedKeyInput `json:"wrappedKeys"`
}

// handleCreateSpace creates a space. No name is accepted: the space's name lives
// encrypted inside its workspace document, so the server never learns it.
func (s *Server) handleCreateSpace(w http.ResponseWriter, r *http.Request) {
	var req createSpaceRequest
	if err := decodeJSON(w, r, maxSmallBody, &req); err != nil {
		writeError(w, err)
		return
	}
	if len(req.WrappedKeys) == 0 {
		writeError(w, badRequest("wrappedKeys must contain at least the calling device's wrapped space key"))
		return
	}

	keys, err := parseWrappedKeys(req.WrappedKeys)
	if err != nil {
		writeError(w, err)
		return
	}

	spaceID, err := s.store.CreateSpace(r.Context(), callerFrom(r.Context()).UserID, keys)
	if err != nil {
		if errors.Is(err, store.ErrForbidden) {
			writeError(w, badRequest("no wrapped key matched an active device of yours, so the space would be undecryptable"))
			return
		}
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": spaceID.String(), "role": store.RoleOwner, "keyEpoch": 1, "headSeq": 0, "workspaceVersion": 0})
}

// handleListSpaces returns the caller's spaces with the space key wrapped for the
// calling device, so that device can start decrypting straight away. A null
// wrappedKey means this device has not been given the key yet.
func (s *Server) handleListSpaces(w http.ResponseWriter, r *http.Request) {
	c := callerFrom(r.Context())
	includeRecovery := r.URL.Query().Get("includeRecoveryKeys") == "true"

	spaces, err := s.store.ListSpaces(r.Context(), c.UserID, c.DeviceID, includeRecovery)
	if err != nil {
		writeError(w, err)
		return
	}

	out := make([]map[string]any, 0, len(spaces))
	for _, sp := range spaces {
		item := map[string]any{"id": sp.ID.String(), "role": sp.Role, "keyEpoch": sp.KeyEpoch, "headSeq": sp.HeadSeq, "oldestSeq": sp.OldestSeq, "workspaceVersion": sp.WorkspaceVersion, "memberCount": sp.MemberCount, "wrappedKey": nilIfEmpty(encodeB64(sp.WrappedKey))}
		if includeRecovery {
			item["recoveryWrappedKey"] = nilIfEmpty(encodeB64(sp.RecoveryWrappedKey))
		}
		out = append(out, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"spaces": out})
}

func (s *Server) handleListMembers(w http.ResponseWriter, r *http.Request) {
	spaceID, err := parseUUIDParam(chi.URLParam(r, "spaceID"), "spaceId")
	if err != nil {
		writeError(w, err)
		return
	}

	members, err := s.store.ListMembers(r.Context(), spaceID)
	if err != nil {
		writeError(w, err)
		return
	}

	out := make([]map[string]any, 0, len(members))
	for _, m := range members {
		out = append(out, map[string]any{"userId": m.UserID.String(), "username": m.Username, "name": m.Name, "avatarUrl": m.AvatarURL, "role": m.Role, "joinedAt": m.JoinedAt.UTC().Format(time.RFC3339)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"members": out})
}

type addMemberRequest struct {
	UserID      string            `json:"userId"`
	Role        string            `json:"role"`
	KeyEpoch    int               `json:"keyEpoch"`
	WrappedKeys []wrappedKeyInput `json:"wrappedKeys"`
}

// handleAddMember invites a member by filing the space key wrapped for each of
// their devices. The invitee's client fetches nothing extra: their next
// GET /spaces already carries the wrapped key for the device asking.
func (s *Server) handleAddMember(w http.ResponseWriter, r *http.Request) {
	spaceID, err := parseUUIDParam(chi.URLParam(r, "spaceID"), "spaceId")
	if err != nil {
		writeError(w, err)
		return
	}

	var req addMemberRequest
	if err := decodeJSON(w, r, maxSmallBody, &req); err != nil {
		writeError(w, err)
		return
	}
	memberID, err := parseUUIDParam(req.UserID, "userId")
	if err != nil {
		writeError(w, err)
		return
	}
	if req.Role != store.RoleEditor && req.Role != store.RoleViewer {
		writeError(w, badRequest("role must be editor or viewer"))
		return
	}
	if len(req.WrappedKeys) == 0 {
		writeError(w, badRequest("wrappedKeys must carry the space key wrapped for the invitee"))
		return
	}

	keys, err := parseWrappedKeys(req.WrappedKeys)
	if err != nil {
		writeError(w, err)
		return
	}

	c := callerFrom(r.Context())
	if err := s.store.AddMember(r.Context(), spaceID, c.UserID, memberID, req.Role, keys, req.KeyEpoch); err != nil {
		switch {
		case errors.Is(err, store.ErrConflict):
			writeError(w, errConflict("already_member_or_stale_epoch", "that user is already a member, or the space key rotated while you were inviting — refetch and retry"))
		case errors.Is(err, store.ErrForbidden):
			writeError(w, badRequest("no wrapped key matched an active device of that user"))
		case errors.Is(err, store.ErrNotFound):
			writeError(w, errNotFound("space not found"))
		default:
			writeError(w, err)
		}
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"spaceId": spaceID.String(), "userId": memberID.String(), "role": req.Role})
}

// handleRemoveMember removes a member (owners) or leaves a space (self). The
// caller's client must then rotate the space key: removal revokes future fetches
// but cannot unlearn the key the member already had.
func (s *Server) handleRemoveMember(w http.ResponseWriter, r *http.Request) {
	spaceID, err := parseUUIDParam(chi.URLParam(r, "spaceID"), "spaceId")
	if err != nil {
		writeError(w, err)
		return
	}
	targetID, err := parseUUIDParam(chi.URLParam(r, "userID"), "userId")
	if err != nil {
		writeError(w, err)
		return
	}

	c := callerFrom(r.Context())
	if targetID != c.UserID && roleFrom(r.Context()) != store.RoleOwner {
		writeError(w, errForbidden("insufficient_role", "only the owner can remove another member"))
		return
	}

	if err := s.store.RemoveMember(r.Context(), spaceID, targetID); err != nil {
		switch {
		case errors.Is(err, store.ErrForbidden):
			writeError(w, errForbidden("owner_immutable", "the owner cannot be removed; transfer or delete the space instead"))
		case errors.Is(err, store.ErrNotFound):
			writeError(w, errNotFound("that user is not a member of this space"))
		default:
			writeError(w, err)
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type rotateKeysRequest struct {
	NewEpoch    int               `json:"newEpoch"`
	WrappedKeys []wrappedKeyInput `json:"wrappedKeys"`
}

// handleRotateSpaceKey advances the space to a new key epoch after a member or
// device was removed. The server checks only that every remaining member's active
// devices received a wrapped key — coverage, never content — and rejects the whole
// rotation otherwise so nobody is silently locked out.
func (s *Server) handleRotateSpaceKey(w http.ResponseWriter, r *http.Request) {
	spaceID, err := parseUUIDParam(chi.URLParam(r, "spaceID"), "spaceId")
	if err != nil {
		writeError(w, err)
		return
	}

	var req rotateKeysRequest
	if err := decodeJSON(w, r, maxSyncBody, &req); err != nil {
		writeError(w, err)
		return
	}
	if req.NewEpoch <= 1 {
		writeError(w, badRequest("newEpoch must be the current epoch plus one"))
		return
	}
	if len(req.WrappedKeys) == 0 {
		writeError(w, badRequest("wrappedKeys must cover every remaining member device"))
		return
	}

	keys := make([]store.RotationKey, 0, len(req.WrappedKeys))
	for i, in := range req.WrappedKeys {
		if in.UserID == nil {
			writeError(w, badRequest("wrappedKeys[%d].userId is required when rotating", i))
			return
		}
		memberID, err := parseUUIDParam(*in.UserID, "wrappedKeys[].userId")
		if err != nil {
			writeError(w, err)
			return
		}
		wrapped, err := decodeB64(in.WrappedKey, "wrappedKeys[].wrappedKey")
		if err != nil {
			writeError(w, err)
			return
		}
		if err := seal.ValidateWrappedKey(wrapped); err != nil {
			writeError(w, badRequest("wrappedKeys[%d]: %v", i, err))
			return
		}

		key := store.RotationKey{UserID: memberID, WrappedKey: wrapped}
		if in.DeviceID != nil {
			deviceID, err := parseUUIDParam(*in.DeviceID, "wrappedKeys[].deviceId")
			if err != nil {
				writeError(w, err)
				return
			}
			key.DeviceID = &deviceID
		}
		keys = append(keys, key)
	}

	if err := s.store.RotateSpaceKey(r.Context(), spaceID, callerFrom(r.Context()).UserID, req.NewEpoch, keys); err != nil {
		switch {
		case errors.Is(err, store.ErrConflict):
			writeError(w, errConflict("epoch_conflict", "the epoch is not current+1, or the rotation left an active member device without a key — refetch the key directory and retry"))
		case errors.Is(err, store.ErrNotFound):
			writeError(w, errNotFound("space not found"))
		default:
			writeError(w, err)
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"spaceId": spaceID.String(), "keyEpoch": req.NewEpoch})
}

func nilIfEmpty(v string) any {
	if v == "" {
		return nil
	}
	return v
}
