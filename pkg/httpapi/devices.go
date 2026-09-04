package httpapi

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/ownspce/backend/pkg/seal"
	"github.com/ownspce/backend/pkg/store"
)

type devicePayload struct {
	ID          string  `json:"id"`
	Label       string  `json:"label"`
	Platform    string  `json:"platform"`
	PublicKey   string  `json:"publicKey"`
	Status      string  `json:"status"`
	ApprovedVia *string `json:"approvedVia"`
	CreatedAt   string  `json:"createdAt"`
	LastSeenAt  *string `json:"lastSeenAt"`
	IsCurrent   bool    `json:"isCurrent"`
}

func toDevicePayload(d store.Device, currentID uuid.UUID) devicePayload {
	var lastSeen *string
	if d.LastSeenAt != nil {
		formatted := d.LastSeenAt.UTC().Format(time.RFC3339)
		lastSeen = &formatted
	}
	return devicePayload{ID: d.ID.String(), Label: d.Label, Platform: d.Platform, PublicKey: encodeB64(d.PublicKey), Status: d.Status, ApprovedVia: d.ApprovedVia, CreatedAt: d.CreatedAt.UTC().Format(time.RFC3339), LastSeenAt: lastSeen, IsCurrent: d.ID == currentID}
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
// example a CLI). Device keys are immutable: a new key is always a new device,
// and it is trusted from creation because the caller has already proved the
// account.
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

	c := callerFrom(r.Context())
	device, err := s.store.RegisterDevice(r.Context(), c.UserID, req.Label, req.Platform, publicKey)
	if err != nil {
		writeError(w, err)
		return
	}
	// Registered by an already-authenticated caller, so it is admitted on the
	// same terms as one registered at sign-in.
	device = s.admitDevice(r.Context(), c.UserID, device)
	writeJSON(w, http.StatusCreated, toDevicePayload(*device, c.DeviceID))
}

// approveWrappedKey is one space key re-wrapped for the device being approved.
type approveWrappedKey struct {
	SpaceID    string `json:"spaceId"`
	KeyEpoch   int    `json:"keyEpoch"`
	WrappedKey string `json:"wrappedKey"`
}

type approveDeviceRequest struct {
	EmailCode string `json:"emailCode"`
	// Recovery is accepted and ignored. The recovery-phrase path is gone, but
	// every deployed client still sends this field on an ordinary approval, and
	// decodeJSON refuses unknown fields — so removing it from the struct turned
	// every device approval into a 400 the moment it shipped. A field a live
	// client still sends is part of the contract until that client stops.
	Recovery    bool                `json:"recovery"`
	WrappedKeys []approveWrappedKey `json:"wrappedKeys"`
}

// handleApproveDevice activates a pending device and gives it the space keys it
// needs. Two paths reach here:
//
//   - an already-active device approves the new one after the user compares
//     fingerprints, and supplies the wraps it produced itself;
//   - the pending device proves the account's email address with a mailed code,
//     and the server re-wraps the escrow copies for it.
//
// The first path is the private one: the server files opaque wraps it cannot
// read. The second is the one that costs something — the server opens the
// account's escrow copies to produce the new wrap, which is the deliberate
// trade that makes a lost-every-device recovery possible at all.
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
	via := store.ApprovedViaDevice
	var escrowKeys []store.WrappedSpaceKey

	switch {
	case req.EmailCode != "":
		if !selfApproval {
			writeError(w, badRequest("an email code activates only the device it was sent for"))
			return
		}
		if len(req.WrappedKeys) > 0 {
			writeError(w, badRequest("an email code carries no wrapped keys; the server produces them"))
			return
		}
		if err := s.consumeDeviceEmailCode(r.Context(), c.UserID, targetID, req.EmailCode); err != nil {
			writeError(w, err)
			return
		}
		device, err := s.store.LiveDevice(r.Context(), targetID)
		if err != nil {
			writeError(w, err)
			return
		}
		escrowKeys, err = s.rewrapFromEscrow(r.Context(), c.UserID, device.PublicKey)
		if err != nil {
			writeError(w, err)
			return
		}
		via = store.ApprovedViaEmail
	case selfApproval:
		writeError(w, errForbidden("approval_required", "a device cannot approve itself; approve it from a device you already use, or prove this account's email address with a code"))
		return
	case c.Status != store.DeviceStatusActive:
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

	device, err := s.store.ApproveDevice(r.Context(), c.UserID, targetID, approver, &via, append(keys, escrowKeys...))
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

// handleDeviceEmailCode mails a code to the account's own address so the device
// asking can let itself in.
//
// Deliberately reachable by a pending device — that is the only device that ever
// needs it. It sends only to the address already on the account, so a pending
// device cannot aim mail anywhere, and the code it gets back activates a device
// without unlocking one byte of anybody's ledger.
func (s *Server) handleDeviceEmailCode(w http.ResponseWriter, r *http.Request) {
	targetID, err := parseUUIDParam(chi.URLParam(r, "deviceID"), "deviceId")
	if err != nil {
		writeError(w, err)
		return
	}

	c := callerFrom(r.Context())
	if targetID != c.DeviceID {
		writeError(w, badRequest("a device can only request a code for itself"))
		return
	}
	if !s.mailer.Configured() {
		writeError(w, errUnavailable("email verification is not configured on this deployment"))
		return
	}

	user, err := s.store.GetUser(r.Context(), c.UserID)
	if err != nil {
		writeError(w, err)
		return
	}
	device, err := s.store.LiveDevice(r.Context(), targetID)
	if err != nil {
		writeError(w, err)
		return
	}

	code, _, err := s.store.IssueEmailCode(r.Context(), user.Email, store.EmailCodePurposeDevice, &c.UserID, &targetID)
	if err != nil {
		if errors.Is(err, store.ErrCodeThrottled) {
			writeError(w, apiError{status: http.StatusTooManyRequests, Code: "rate_limited", Message: "too many codes sent to this address; wait an hour"})
			return
		}
		writeError(w, err)
		return
	}

	if err := s.mailer.SendDeviceCode(r.Context(), user.Email, code, device.Label, store.EmailCodeTTL()); err != nil {
		log.Printf("send device code: %v", err)
		writeError(w, errUnavailable("could not send the code; try again shortly"))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// consumeDeviceEmailCode checks a mailed code against the device it was issued
// for.
// Args: ctx, userID, the device being activated, the code as typed
// Returns: nil when the code was this device's and is now spent, an apiError
// otherwise
// Handles: a code minted for a different device of the same account, which is
// refused rather than accepted — otherwise one code would admit any device
func (s *Server) consumeDeviceEmailCode(ctx context.Context, userID, deviceID uuid.UUID, code string) error {
	user, err := s.store.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	if _, err := s.store.ConsumeEmailCode(ctx, user.Email, store.EmailCodePurposeDevice, code, &deviceID); err != nil {
		switch {
		case errors.Is(err, store.ErrCodeThrottled):
			return errForbidden("code_exhausted", "too many wrong codes; ask for a new one")
		case errors.Is(err, store.ErrCodeInvalid):
			return errUnauthorized("that code is wrong or has expired; ask for a new one")
		default:
			return err
		}
	}
	return nil
}

// rewrapFromEscrow opens the account's escrow copy of every household key and
// seals each one to a device that has just proved the account's email address.
//
// This is the one place in the system where the server touches a key that can
// open somebody's ledger, and it is the price of the product decision that a
// person who has lost every device gets their money back. It runs only after a
// mailed code has been consumed.
// Args: ctx, userID, the new device's X25519 public key
// Returns: one wrapped key per household that could be recovered
// Handles: an escrow wrap sealed to a key this deployment can no longer open
// (an account that predates escrow), which is skipped rather than failing the
// whole activation — the device still gets in, and the households it could not
// be given land on the awaiting-key screen where a member can hand them over
func (s *Server) rewrapFromEscrow(ctx context.Context, userID uuid.UUID, devicePublicKey []byte) ([]store.WrappedSpaceKey, error) {
	if !s.escrow.Configured() {
		return nil, errUnavailable("email recovery is not configured on this deployment")
	}

	escrowPublic, escrowSealed, err := s.store.EscrowKey(ctx, userID)
	if err != nil {
		return nil, err
	}
	if len(escrowPublic) == 0 || len(escrowSealed) == 0 {
		return nil, nil
	}

	wraps, err := s.store.ListEscrowWraps(ctx, userID)
	if err != nil {
		return nil, err
	}

	out := make([]store.WrappedSpaceKey, 0, len(wraps))
	for _, wrap := range wraps {
		rewrapped, err := s.escrow.RewrapTo(escrowSealed, escrowPublic, wrap.WrappedKey, devicePublicKey)
		if err != nil {
			log.Printf("escrow rewrap skipped space %s for user %s: %v", wrap.SpaceID, userID, err)
			continue
		}
		out = append(out, store.WrappedSpaceKey{SpaceID: wrap.SpaceID, KeyEpoch: wrap.KeyEpoch, WrappedKey: rewrapped})
	}
	return out, nil
}

// ensureEscrowKey mints the account's escrow key if it has none, and returns the
// public half either way.
//
// Called on every sign-in rather than only at account creation, so accounts made
// before escrow existed pick one up the next time their owner appears, and so a
// deployment that had no master key configured heals once it does.
//
// The return value matters more than it looks. Clients wrap a new household key
// to whatever `recoveryPublicKey` the session handed them, so a first session
// that answered with an empty one would produce a household with no escrow wrap
// — unrecoverable, which is the single thing this whole path exists to prevent.
// Args: ctx, userID
// Returns: the account's escrow public key, or nil when there is none to be had
// Handles: a deployment with no master key, which returns nil quietly — sign-in
// must not fail because recovery is unavailable
func (s *Server) ensureEscrowKey(ctx context.Context, userID uuid.UUID) []byte {
	if !s.escrow.Configured() {
		return nil
	}

	existing, sealedPrivate, err := s.store.EscrowKey(ctx, userID)
	if err != nil {
		log.Printf("read escrow key for %s: %v", userID, err)
		return nil
	}
	if len(sealedPrivate) > 0 {
		return existing
	}

	public, sealed, err := s.escrow.NewAccountKey()
	if err != nil {
		log.Printf("mint escrow key for %s: %v", userID, err)
		return nil
	}
	installed, err := s.store.SetEscrowKey(ctx, userID, public, sealed)
	if err != nil {
		log.Printf("store escrow key for %s: %v", userID, err)
		return nil
	}
	if !installed {
		// Another sign-in won the race; theirs is the key that counts.
		current, _, err := s.store.EscrowKey(ctx, userID)
		if err != nil {
			return nil
		}
		return current
	}
	return public
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
	writeJSON(w, http.StatusOK, map[string]any{"userId": userID.String(), "devices": devices, "recoveryPublicKey": encodeB64(dir.EscrowPublicKey)})
}
