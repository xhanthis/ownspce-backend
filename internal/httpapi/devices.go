package httpapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/ownspce/backend/internal/seal"
	"github.com/ownspce/backend/internal/store"
)

type devicePayload struct {
	ID         string  `json:"id"`
	Label      string  `json:"label"`
	Platform   string  `json:"platform"`
	PublicKey  string  `json:"publicKey"`
	Status     string  `json:"status"`
	CreatedAt  string  `json:"createdAt"`
	LastSeenAt *string `json:"lastSeenAt"`
	IsCurrent  bool    `json:"isCurrent"`
}

func toDevicePayload(d store.Device, currentID uuid.UUID) devicePayload {
	var lastSeen *string
	if d.LastSeenAt != nil {
		formatted := d.LastSeenAt.UTC().Format(time.RFC3339)
		lastSeen = &formatted
	}
	return devicePayload{ID: d.ID.String(), Label: d.Label, Platform: d.Platform, PublicKey: encodeB64(d.PublicKey), Status: d.Status, CreatedAt: d.CreatedAt.UTC().Format(time.RFC3339), LastSeenAt: lastSeen, IsCurrent: d.ID == currentID}
}

// handleListDevices lists the account's live devices, including pending ones so an
// already-trusted device can offer to approve a new one.
func (s *Server) handleListDevices(w http.ResponseWriter, r *http.Request) {
	c := callerFrom(r.Context())
	devices, err := s.store.ListDevices(r.Context(), c.UserID)
	if err != nil {
		writeError(w, err)
		return
	}

	out := make([]devicePayload, 0, len(devices))
	for _, d := range devices {
		out = append(out, toDevicePayload(d, c.DeviceID))
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": out})
}

type registerDeviceRequest struct {
	Label     string `json:"label"`
	Platform  string `json:"platform"`
	PublicKey string `json:"publicKey"`
}

// handleRegisterDevice adds a device to an already-authenticated account (for
// example a CLI). Device keys are immutable: a new key is always a new device.
func (s *Server) handleRegisterDevice(w http.ResponseWriter, r *http.Request) {
	var req registerDeviceRequest
	if err := decodeJSON(w, r, maxSmallBody, &req); err != nil {
		writeError(w, err)
		return
	}

	publicKey, err := decodeB64(req.PublicKey, "publicKey")
	if err != nil {
		writeError(w, err)
		return
	}
	if err := seal.ValidatePublicKey(publicKey); err != nil {
		writeError(w, badRequest("%v", err))
		return
	}

	device, err := s.store.RegisterDevice(r.Context(), callerFrom(r.Context()).UserID, req.Label, req.Platform, publicKey)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, toDevicePayload(*device, callerFrom(r.Context()).DeviceID))
}

type approveDeviceRequest struct {
	Recovery    bool `json:"recovery"`
	WrappedKeys []struct {
		SpaceID    string `json:"spaceId"`
		KeyEpoch   int    `json:"keyEpoch"`
		WrappedKey string `json:"wrappedKey"`
	} `json:"wrappedKeys"`
}

// handleApproveDevice activates a pending device and stores the space keys wrapped
// to it. Two paths reach here, matching the two recovery routes:
//   - an already-active device approves the new one after the user compares
//     fingerprints, and supplies the wraps;
//   - the pending device itself supplies wraps it produced from the recovery
//     phrase (recovery: true), having unwrapped the recovery-key copies locally.
//
// Either way the server only files opaque wrapped keys — it cannot tell whether
// the wraps are correct, and cannot produce them itself.
func (s *Server) handleApproveDevice(w http.ResponseWriter, r *http.Request) {
	targetID, err := parseUUIDParam(chi.URLParam(r, "deviceID"), "deviceId")
	if err != nil {
		writeError(w, err)
		return
	}

	var req approveDeviceRequest
	if err := decodeJSON(w, r, maxSmallBody, &req); err != nil {
		writeError(w, err)
		return
	}

	c := callerFrom(r.Context())
	selfApproval := c.DeviceID == targetID
	switch {
	case selfApproval && !req.Recovery:
		writeError(w, errForbidden("approval_required", "a device cannot approve itself unless it proves recovery-phrase possession by supplying re-wrapped keys with recovery: true"))
		return
	case !selfApproval && c.Status != store.DeviceStatusActive:
		writeError(w, errForbidden("device_pending", "only an active device can approve another device"))
		return
	}

	keys := make([]store.WrappedSpaceKey, 0, len(req.WrappedKeys))
	for i, k := range req.WrappedKeys {
		spaceID, err := parseUUIDParam(k.SpaceID, "wrappedKeys[].spaceId")
		if err != nil {
			writeError(w, err)
			return
		}
		wrapped, err := decodeB64(k.WrappedKey, "wrappedKeys[].wrappedKey")
		if err != nil {
			writeError(w, err)
			return
		}
		if err := seal.ValidateWrappedKey(wrapped); err != nil {
			writeError(w, badRequest("wrappedKeys[%d]: %v", i, err))
			return
		}
		if k.KeyEpoch <= 0 {
			writeError(w, badRequest("wrappedKeys[%d].keyEpoch must be positive", i))
			return
		}
		keys = append(keys, store.WrappedSpaceKey{SpaceID: spaceID, KeyEpoch: k.KeyEpoch, WrappedKey: wrapped})
	}

	var approver *uuid.UUID
	if !selfApproval {
		approver = &c.DeviceID
	}

	device, err := s.store.ApproveDevice(r.Context(), c.UserID, targetID, approver, keys)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, errNotFound("device not found for this account"))
			return
		}
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toDevicePayload(*device, c.DeviceID))
}

// handlePendingKeys tells an approving device exactly which spaces still need a
// key wrapped for the target device, and at which epoch.
func (s *Server) handlePendingKeys(w http.ResponseWriter, r *http.Request) {
	targetID, err := parseUUIDParam(chi.URLParam(r, "deviceID"), "deviceId")
	if err != nil {
		writeError(w, err)
		return
	}

	c := callerFrom(r.Context())
	target, err := s.store.LiveDevice(r.Context(), targetID)
	if err != nil || target.UserID != c.UserID {
		writeError(w, errNotFound("device not found for this account"))
		return
	}

	spaces, err := s.store.PendingKeySpaces(r.Context(), c.UserID, targetID)
	if err != nil {
		writeError(w, err)
		return
	}

	out := make([]map[string]any, 0, len(spaces))
	for _, sp := range spaces {
		out = append(out, map[string]any{"spaceId": sp.ID.String(), "keyEpoch": sp.KeyEpoch})
	}
	writeJSON(w, http.StatusOK, map[string]any{"deviceId": targetID.String(), "publicKey": encodeB64(target.PublicKey), "spaces": out})
}

// handleRevokeDevice revokes a device: its refresh tokens die, the space keys
// wrapped to it are deleted, and its next request is rejected by the auth
// middleware. The client should then rotate the keys of every space that device
// could read, since revocation cannot make it forget what it already holds.
func (s *Server) handleRevokeDevice(w http.ResponseWriter, r *http.Request) {
	targetID, err := parseUUIDParam(chi.URLParam(r, "deviceID"), "deviceId")
	if err != nil {
		writeError(w, err)
		return
	}

	if err := s.store.RevokeDevice(r.Context(), callerFrom(r.Context()).UserID, targetID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, errNotFound("device not found for this account"))
			return
		}
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleKeyDirectory returns a user's public encryption keys so an owner can wrap
// a space key for them. Public keys only — the server never sees a private key.
func (s *Server) handleKeyDirectory(w http.ResponseWriter, r *http.Request) {
	userID, err := parseUUIDParam(chi.URLParam(r, "userID"), "userId")
	if err != nil {
		writeError(w, err)
		return
	}

	dir, err := s.store.PublicKeyDirectory(r.Context(), userID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, errNotFound("no such user"))
			return
		}
		writeError(w, err)
		return
	}

	devices := make([]map[string]string, 0, len(dir.Devices))
	for _, d := range dir.Devices {
		devices = append(devices, map[string]string{"deviceId": d.ID.String(), "publicKey": encodeB64(d.PublicKey)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"userId": userID.String(), "devices": devices, "recoveryPublicKey": encodeB64(dir.RecoveryPublicKey)})
}
