package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/ownspce/backend/pkg/ratelimit"
	"github.com/ownspce/backend/pkg/seal"
	"github.com/ownspce/backend/pkg/store"
)

// The money surface moves ciphertext, like every other data route here.
//
// An earlier version of Kosh stored amounts, categories and notes in the clear
// so the server could compute budgets and settle-up. It read well in a README
// and it meant an operator with database access could read a family's ledger.
// That trade is withdrawn: a household is a space, its records are sealed under
// the space key, and the arithmetic runs on the device where money-core already
// lived.
//
// Two consequences show up in this file. Money routes now sit under
// requireActiveDevice, because a device with no wrapped space key cannot open a
// single row and letting it in would only produce a screen full of nothing. And
// there is no summary endpoint, no computed budget usage and no search: those
// were sums and substring matches over plaintext, and they are gone with it.

// dateFormat is the wire format for every money date. Entries carry a calendar
// date, never a timestamp: a dinner logged in Bengaluru belongs to the day the
// household says it happened, and must not slide when a member opens the app
// from another timezone. It is the one field of an entry the server can read,
// because a ledger is queried by period and the alternative is shipping every
// row a household has ever written on every load.
const dateFormat = "2006-01-02"

// inviteTokenBytes is the entropy behind a household invite link.
const inviteTokenBytes = 32

// inviteTTL bounds how long an emailed invitation stays redeemable.
const inviteTTL = 14 * 24 * time.Hour

// maxBatchRecords caps one sealed write. A CSV import of a year of a family's
// spending fits in two or three requests; an unbounded batch would let one
// caller hold a transaction open over thousands of rows.
const maxBatchRecords = 200

// defaultEntryPage is the page size when a client does not ask for one.
const defaultEntryPage = 200

// moneyRoutes mounts the whole money surface. It is called from routes() so the
// wiring is one line there and every handler below stays in this file.
//
// The tree hangs off /money rather than extending /spaces/{spaceID}, because
// chi mounts a subrouter over an entire subtree: adding /spaces/{spaceID}/money
// alongside the existing /spaces/{spaceID} router would be a second Mount on the
// same node and panic at startup.
func (s *Server) moneyRoutes(r chi.Router) {
	r.Route("/money", func(r chi.Router) {
		r.With(s.rateLimit(ratelimit.MoneyRead, subjectUser)).Get("/households", s.handleListHouseholds)
		r.With(s.rateLimit(ratelimit.MoneyWrite, subjectUser)).Post("/households", s.handleCreateHousehold)
		r.With(s.rateLimit(ratelimit.MoneyWrite, subjectUser)).Post("/invites/accept", s.handleAcceptInvite)

		r.Route("/households/{spaceID}", func(r chi.Router) {
			r.With(s.requireSpaceRole(store.RoleOwner), s.rateLimit(ratelimit.MoneyWrite, subjectUser)).Post("/enable", s.handleEnableMoney)

			r.Group(func(r chi.Router) {
				r.Use(s.requireMoneyRole(store.RoleViewer), s.rateLimit(ratelimit.MoneyRead, subjectUser))
				r.Get("/vault", s.handleGetVault)
				r.Get("/entries", s.handleListEntries)
				r.Get("/objects", s.handleListObjects)
				r.Get("/key-gaps", s.handleKeyGaps)
			})

			r.Group(func(r chi.Router) {
				r.Use(s.requireMoneyRole(store.RoleEditor), s.rateLimit(ratelimit.MoneyWrite, subjectUser))
				r.Put("/vault", s.handlePutVault)
				r.Post("/entries", s.handlePutEntries)
				r.Delete("/entries/{clientID}", s.handleDeleteEntry)
				r.Post("/objects", s.handlePutObjects)
				r.Delete("/objects/{kind}/{clientID}", s.handleDeleteObject)
			})

			r.Group(func(r chi.Router) {
				r.Use(s.requireMoneyRole(store.RoleOwner))
				r.With(s.rateLimit(ratelimit.MoneyWrite, subjectUser)).Post("/keys", s.handleGrantKeys)
				r.With(s.rateLimit(ratelimit.MoneyRead, subjectUser)).Get("/invites", s.handleListInvites)
				r.With(s.rateLimit(ratelimit.MoneyInvite, subjectUser)).Post("/invites", s.handleCreateInvite)
				r.With(s.rateLimit(ratelimit.MoneyWrite, subjectUser)).Delete("/invites/{inviteID}", s.handleRevokeInvite)
			})
		})
	})
}

// requireMoneyRole authorizes a money route, resolving membership and the
// presence of a vault in a single query and putting the role in the context.
func (s *Server) requireMoneyRole(minRole string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			spaceID, err := parseUUIDParam(chi.URLParam(r, "spaceID"), "spaceId")
			if err != nil {
				writeError(w, err)
				return
			}

			role, err := s.store.MoneyRole(r.Context(), spaceID, callerFrom(r.Context()).UserID)
			if err != nil {
				if errors.Is(err, store.ErrNotFound) {
					writeError(w, errNotFound("no money household here"))
					return
				}
				writeError(w, err)
				return
			}
			if !store.RoleAtLeast(role, minRole) {
				writeError(w, errForbidden("insufficient_role", fmt.Sprintf("this action requires the %s role", minRole)))
				return
			}

			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKeyRole, role)))
		})
	}
}

// spaceIDFrom re-reads the space id a money route already validated.
func spaceIDFrom(r *http.Request) uuid.UUID {
	id, _ := uuid.Parse(chi.URLParam(r, "spaceID"))
	return id
}

// parseDate reads one YYYY-MM-DD query or body field.
func parseDate(raw, field string) (time.Time, error) {
	parsed, err := time.Parse(dateFormat, strings.TrimSpace(raw))
	if err != nil {
		return time.Time{}, badRequest("%s must be a date as YYYY-MM-DD", field)
	}
	return parsed, nil
}

// parseSealed decodes and length-checks one sealed record.
//
// Length is the server's entire content-related validation surface: clients pad
// plaintext into fixed buckets before encrypting, so a stored row's size says
// nothing about what it holds, and the server enforces that by refusing anything
// that is not a bucket plus AEAD overhead.
// Args: raw (base64), field (name used in the error)
// Returns: ciphertext bytes, error
func parseSealed(raw, field string) ([]byte, error) {
	ciphertext, err := decodeB64(raw, field)
	if err != nil {
		return nil, err
	}
	if _, err := seal.ValidateMoneyCiphertext(ciphertext); err != nil {
		return nil, errTooLarge("bucket_violation", fmt.Sprintf("%s: %v", field, err))
	}
	return ciphertext, nil
}

func vaultJSON(v *store.MoneyVault) map[string]any {
	return map[string]any{"spaceId": v.SpaceID, "keyEpoch": v.KeyEpoch, "version": v.Version, "ciphertext": encodeB64(v.Ciphertext), "updatedAt": v.UpdatedAt.UTC().Format(time.RFC3339)}
}

func entryJSON(e store.MoneyEntry) map[string]any {
	return map[string]any{"id": e.ID, "clientId": e.ClientID, "occurredOn": e.OccurredOn.UTC().Format(dateFormat), "keyEpoch": e.KeyEpoch, "ciphertext": encodeB64(e.Ciphertext), "createdBy": e.CreatedBy, "updatedAt": e.UpdatedAt.UTC().Format(time.RFC3339)}
}

func objectJSON(o store.MoneyObject) map[string]any {
	return map[string]any{"id": o.ID, "kind": o.Kind, "clientId": o.ClientID, "sortOrder": o.SortOrder, "keyEpoch": o.KeyEpoch, "ciphertext": encodeB64(o.Ciphertext), "updatedAt": o.UpdatedAt.UTC().Format(time.RFC3339)}
}

// handleListHouseholds returns the caller's households, each with the space key
// wrapped for the calling device. A null wrappedKey means this device has not
// been approved for that household yet, which the client shows as a waiting
// state rather than an empty ledger.
func (s *Server) handleListHouseholds(w http.ResponseWriter, r *http.Request) {
	c := callerFrom(r.Context())
	households, err := s.store.ListMoneyHouseholds(r.Context(), c.UserID, c.DeviceID)
	if err != nil {
		writeError(w, err)
		return
	}

	out := make([]map[string]any, 0, len(households))
	for _, h := range households {
		out = append(out, map[string]any{"spaceId": h.SpaceID, "role": h.Role, "keyEpoch": h.KeyEpoch, "memberCount": h.MemberCount, "vaultVersion": h.VaultVersion, "wrappedKey": nilIfEmpty(encodeB64(h.WrappedKey))})
	}
	writeJSON(w, http.StatusOK, map[string]any{"households": out})
}

type createHouseholdRequest struct {
	SpaceID     string            `json:"spaceId"`
	WrappedKeys []wrappedKeyInput `json:"wrappedKeys"`
	Ciphertext  string            `json:"ciphertext"`
}

// handleCreateHousehold creates a household in one call: the space, the owner's
// membership, the space key wrapped for the owner's devices, and the sealed
// settings document.
//
// No name, currency or rule is accepted in the clear. All of it lives inside the
// ciphertext, which is why the client must seal the document before it can
// create the household rather than after — and why the id is minted by the
// client: it is bound into the sealed document's authenticated data, so it has
// to exist before the document does.
func (s *Server) handleCreateHousehold(w http.ResponseWriter, r *http.Request) {
	var req createHouseholdRequest
	if err := decodeJSON(w, r, maxSmallBody, &req); err != nil {
		writeError(w, err)
		return
	}
	spaceID, err := parseUUIDParam(req.SpaceID, "spaceId")
	if err != nil {
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
	ciphertext, err := parseSealed(req.Ciphertext, "ciphertext")
	if err != nil {
		writeError(w, err)
		return
	}

	if err := s.store.CreateMoneyHousehold(r.Context(), spaceID, callerFrom(r.Context()).UserID, keys, ciphertext); err != nil {
		switch {
		case errors.Is(err, store.ErrForbidden):
			writeError(w, badRequest("no wrapped key matched an active device of yours, so the household would be unopenable"))
		case errors.Is(err, store.ErrConflict):
			writeError(w, errConflict("space_exists", "that household id is already taken; mint a new one"))
		default:
			writeError(w, err)
		}
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"spaceId": spaceID, "role": store.RoleOwner, "keyEpoch": 1, "memberCount": 1, "vaultVersion": 1})
}

type enableMoneyRequest struct {
	KeyEpoch   int    `json:"keyEpoch"`
	Ciphertext string `json:"ciphertext"`
}

// handleEnableMoney adds a ledger to a space that already exists, so a household
// that already shares notes does not end up with a second membership list to keep
// in sync.
func (s *Server) handleEnableMoney(w http.ResponseWriter, r *http.Request) {
	var req enableMoneyRequest
	if err := decodeJSON(w, r, maxSmallBody, &req); err != nil {
		writeError(w, err)
		return
	}
	if req.KeyEpoch <= 0 {
		writeError(w, badRequest("keyEpoch must be the space's current key epoch"))
		return
	}
	ciphertext, err := parseSealed(req.Ciphertext, "ciphertext")
	if err != nil {
		writeError(w, err)
		return
	}

	vault, err := s.store.EnableMoney(r.Context(), spaceIDFrom(r), callerFrom(r.Context()).UserID, req.KeyEpoch, ciphertext)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, errConflict("already_enabled_or_stale_epoch", "money is already enabled here, or the space key rotated while you were enabling it"))
			return
		}
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, vaultJSON(vault))
}

func (s *Server) handleGetVault(w http.ResponseWriter, r *http.Request) {
	vault, err := s.store.MoneyVaultFor(r.Context(), spaceIDFrom(r))
	if err != nil {
		writeError(w, storeError(err, "no money household here", "", "", "", ""))
		return
	}
	writeJSON(w, http.StatusOK, vaultJSON(vault))
}

type putVaultRequest struct {
	Version    int64  `json:"version"`
	KeyEpoch   int    `json:"keyEpoch"`
	Ciphertext string `json:"ciphertext"`
}

// handlePutVault replaces the sealed settings document under optimistic
// concurrency. Two members editing household rules at the same moment must not
// silently overwrite each other, so the loser is told to re-read and retry.
func (s *Server) handlePutVault(w http.ResponseWriter, r *http.Request) {
	var req putVaultRequest
	if err := decodeJSON(w, r, maxSmallBody, &req); err != nil {
		writeError(w, err)
		return
	}
	if req.Version <= 0 {
		writeError(w, badRequest("version must be the version you last read"))
		return
	}
	if req.KeyEpoch <= 0 {
		writeError(w, badRequest("keyEpoch must be the epoch you sealed against"))
		return
	}
	ciphertext, err := parseSealed(req.Ciphertext, "ciphertext")
	if err != nil {
		writeError(w, err)
		return
	}

	vault, err := s.store.PutMoneyVault(r.Context(), spaceIDFrom(r), req.Version, req.KeyEpoch, ciphertext)
	if err != nil {
		writeError(w, storeError(err, "no money household here", "version_conflict", "someone changed the household settings while you were editing; re-read and retry", "", ""))
		return
	}
	writeJSON(w, http.StatusOK, vaultJSON(vault))
}

// handleListEntries returns one page of sealed ledger rows for a period.
//
// There is no scope or search parameter. Both used to be server-side filters on
// plaintext — who paid, and whether a note contained a word — and neither is
// something the server can answer any more. The client filters after decrypting.
func (s *Server) handleListEntries(w http.ResponseWriter, r *http.Request) {
	from, err := parseDate(r.URL.Query().Get("from"), "from")
	if err != nil {
		writeError(w, err)
		return
	}
	to, err := parseDate(r.URL.Query().Get("to"), "to")
	if err != nil {
		writeError(w, err)
		return
	}
	if to.Before(from) {
		writeError(w, badRequest("to must not be before from"))
		return
	}

	filter := store.MoneyEntryFilter{SpaceID: spaceIDFrom(r), From: from, To: to, Limit: defaultEntryPage}
	if raw := r.URL.Query().Get("limit"); raw != "" {
		limit, convErr := strconv.Atoi(raw)
		if convErr != nil || limit <= 0 || limit > 500 {
			writeError(w, badRequest("limit must be between 1 and 500"))
			return
		}
		filter.Limit = limit
	}
	if raw := r.URL.Query().Get("cursor"); raw != "" {
		date, id, cursorErr := parseEntryCursor(raw)
		if cursorErr != nil {
			writeError(w, cursorErr)
			return
		}
		filter.CursorDate, filter.CursorID, filter.HasCursor = date, id, true
	}

	entries, next, err := s.store.ListMoneyEntries(r.Context(), filter)
	if err != nil {
		writeError(w, err)
		return
	}

	out := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		out = append(out, entryJSON(e))
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": out, "nextCursor": next})
}

// parseEntryCursor reads the "YYYY-MM-DD|uuid" position from a previous page.
func parseEntryCursor(raw string) (time.Time, uuid.UUID, error) {
	date, id, found := strings.Cut(raw, "|")
	if !found {
		return time.Time{}, uuid.Nil, badRequest("cursor is not a cursor this endpoint issued")
	}
	parsedDate, err := parseDate(date, "cursor")
	if err != nil {
		return time.Time{}, uuid.Nil, err
	}
	parsedID, err := parseUUIDParam(id, "cursor")
	if err != nil {
		return time.Time{}, uuid.Nil, err
	}
	return parsedDate, parsedID, nil
}

type sealedEntryInput struct {
	ClientID   string `json:"clientId"`
	OccurredOn string `json:"occurredOn"`
	Ciphertext string `json:"ciphertext"`
}

type putEntriesRequest struct {
	Entries []sealedEntryInput `json:"entries"`
}

// handlePutEntries upserts a batch of sealed ledger rows.
//
// Batched because the two writes that matter are a CSV import and a
// reconciliation after being offline, and doing either one row per request turns
// a hundred entries into a hundred round trips. Keyed by the client's own id, so
// a retry after a dropped response updates the row it already created instead of
// logging the same dinner twice.
func (s *Server) handlePutEntries(w http.ResponseWriter, r *http.Request) {
	var req putEntriesRequest
	if err := decodeJSON(w, r, maxSyncBody, &req); err != nil {
		writeError(w, err)
		return
	}
	if len(req.Entries) == 0 {
		writeError(w, badRequest("entries must contain at least one record"))
		return
	}
	if len(req.Entries) > maxBatchRecords {
		writeError(w, badRequest("entries must contain at most %d records per request", maxBatchRecords))
		return
	}

	records := make([]store.SealedRecord, 0, len(req.Entries))
	seen := make(map[uuid.UUID]bool, len(req.Entries))
	for i, in := range req.Entries {
		clientID, err := parseUUIDParam(in.ClientID, fmt.Sprintf("entries[%d].clientId", i))
		if err != nil {
			writeError(w, err)
			return
		}
		// One batch is one statement per record inside a single transaction, and
		// two upserts of the same key would deadlock against each other.
		if seen[clientID] {
			writeError(w, badRequest("entries[%d].clientId appears twice in this batch", i))
			return
		}
		seen[clientID] = true

		occurredOn, err := parseDate(in.OccurredOn, fmt.Sprintf("entries[%d].occurredOn", i))
		if err != nil {
			writeError(w, err)
			return
		}
		ciphertext, err := parseSealed(in.Ciphertext, fmt.Sprintf("entries[%d].ciphertext", i))
		if err != nil {
			writeError(w, err)
			return
		}
		records = append(records, store.SealedRecord{ClientID: clientID, OccurredOn: occurredOn, Ciphertext: ciphertext})
	}

	stored, err := s.store.PutMoneyEntries(r.Context(), spaceIDFrom(r), callerFrom(r.Context()).UserID, records)
	if err != nil {
		writeError(w, storeError(err, "no money household here", "", "", "", ""))
		return
	}

	out := make([]map[string]any, 0, len(stored))
	for _, e := range stored {
		out = append(out, entryJSON(e))
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": out})
}

func (s *Server) handleDeleteEntry(w http.ResponseWriter, r *http.Request) {
	clientID, err := parseUUIDParam(chi.URLParam(r, "clientID"), "clientId")
	if err != nil {
		writeError(w, err)
		return
	}
	if err := s.store.DeleteMoneyEntry(r.Context(), spaceIDFrom(r), clientID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListObjects(w http.ResponseWriter, r *http.Request) {
	kind := strings.TrimSpace(r.URL.Query().Get("kind"))
	if kind != "" && !store.MoneyObjectKinds[kind] {
		writeError(w, badRequest("kind must be one of category, account, budget, bill, holding"))
		return
	}

	objects, err := s.store.ListMoneyObjects(r.Context(), spaceIDFrom(r), kind)
	if err != nil {
		writeError(w, err)
		return
	}

	out := make([]map[string]any, 0, len(objects))
	for _, o := range objects {
		out = append(out, objectJSON(o))
	}
	writeJSON(w, http.StatusOK, map[string]any{"objects": out})
}

type sealedObjectInput struct {
	Kind       string `json:"kind"`
	ClientID   string `json:"clientId"`
	SortOrder  int    `json:"sortOrder"`
	Ciphertext string `json:"ciphertext"`
}

type putObjectsRequest struct {
	Objects []sealedObjectInput `json:"objects"`
}

// handlePutObjects upserts a batch of sealed categories, accounts, budgets,
// bills or holdings. A new household seeds a dozen categories in one call.
func (s *Server) handlePutObjects(w http.ResponseWriter, r *http.Request) {
	var req putObjectsRequest
	if err := decodeJSON(w, r, maxSyncBody, &req); err != nil {
		writeError(w, err)
		return
	}
	if len(req.Objects) == 0 {
		writeError(w, badRequest("objects must contain at least one record"))
		return
	}
	if len(req.Objects) > maxBatchRecords {
		writeError(w, badRequest("objects must contain at most %d records per request", maxBatchRecords))
		return
	}

	type objectKey struct {
		kind string
		id   uuid.UUID
	}
	records := make([]store.SealedRecord, 0, len(req.Objects))
	seen := make(map[objectKey]bool, len(req.Objects))
	for i, in := range req.Objects {
		if !store.MoneyObjectKinds[in.Kind] {
			writeError(w, badRequest("objects[%d].kind must be one of category, account, budget, bill, holding", i))
			return
		}
		clientID, err := parseUUIDParam(in.ClientID, fmt.Sprintf("objects[%d].clientId", i))
		if err != nil {
			writeError(w, err)
			return
		}
		key := objectKey{kind: in.Kind, id: clientID}
		if seen[key] {
			writeError(w, badRequest("objects[%d] repeats a kind and clientId already in this batch", i))
			return
		}
		seen[key] = true

		ciphertext, err := parseSealed(in.Ciphertext, fmt.Sprintf("objects[%d].ciphertext", i))
		if err != nil {
			writeError(w, err)
			return
		}
		records = append(records, store.SealedRecord{Kind: in.Kind, ClientID: clientID, SortOrder: in.SortOrder, Ciphertext: ciphertext})
	}

	stored, err := s.store.PutMoneyObjects(r.Context(), spaceIDFrom(r), callerFrom(r.Context()).UserID, records)
	if err != nil {
		writeError(w, storeError(err, "no money household here", "", "", "", ""))
		return
	}

	out := make([]map[string]any, 0, len(stored))
	for _, o := range stored {
		out = append(out, objectJSON(o))
	}
	writeJSON(w, http.StatusOK, map[string]any{"objects": out})
}

func (s *Server) handleDeleteObject(w http.ResponseWriter, r *http.Request) {
	kind := chi.URLParam(r, "kind")
	if !store.MoneyObjectKinds[kind] {
		writeError(w, badRequest("kind must be one of category, account, budget, bill, holding"))
		return
	}
	clientID, err := parseUUIDParam(chi.URLParam(r, "clientID"), "clientId")
	if err != nil {
		writeError(w, err)
		return
	}
	if err := s.store.DeleteMoneyObject(r.Context(), spaceIDFrom(r), kind, clientID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleKeyGaps lists everyone in the household holding no wrapped space key at
// the current epoch, with the public key to wrap it to.
//
// This is what an emailed invite turns into under end-to-end encryption. The
// invitee accepts and becomes a member; membership is not a key, so somebody who
// already holds the ledger has to wrap it for them. The response is public keys
// and names — the same material GET /keys/{userID} already gives any active
// device — never anything sealed.
func (s *Server) handleKeyGaps(w http.ResponseWriter, r *http.Request) {
	gaps, err := s.store.MoneyKeyGaps(r.Context(), spaceIDFrom(r))
	if err != nil {
		writeError(w, err)
		return
	}

	out := make([]map[string]any, 0, len(gaps))
	for _, g := range gaps {
		out = append(out, map[string]any{"userId": g.UserID, "deviceId": g.DeviceID, "publicKey": encodeB64(g.PublicKey), "name": g.Name, "username": g.Username, "recovery": g.DeviceID == nil})
	}
	writeJSON(w, http.StatusOK, map[string]any{"gaps": out})
}

type grantKeysRequest struct {
	KeyEpoch    int               `json:"keyEpoch"`
	WrappedKeys []wrappedKeyInput `json:"wrappedKeys"`
}

// handleGrantKeys files space keys wrapped for members who had none.
//
// Deliberately not a rotation: rotation takes access away and demands complete
// coverage of every remaining device, while this hands access out one member at
// a time as invitations are accepted. The epoch must be current, so a grant
// computed against a key that has since rotated is refused rather than filing a
// wrap nobody can use.
func (s *Server) handleGrantKeys(w http.ResponseWriter, r *http.Request) {
	var req grantKeysRequest
	if err := decodeJSON(w, r, maxSyncBody, &req); err != nil {
		writeError(w, err)
		return
	}
	if req.KeyEpoch <= 0 {
		writeError(w, badRequest("keyEpoch must be the household's current key epoch"))
		return
	}
	if len(req.WrappedKeys) == 0 {
		writeError(w, badRequest("wrappedKeys must contain at least one wrapped space key"))
		return
	}

	keys := make([]store.RotationKey, 0, len(req.WrappedKeys))
	for i, in := range req.WrappedKeys {
		if in.UserID == nil {
			writeError(w, badRequest("wrappedKeys[%d].userId is required", i))
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

	granted, err := s.store.GrantSpaceKeys(r.Context(), spaceIDFrom(r), callerFrom(r.Context()).UserID, req.KeyEpoch, keys)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrConflict):
			writeError(w, errConflict("stale_epoch", "the household key rotated while you were wrapping; refetch the gaps and retry"))
		case errors.Is(err, store.ErrForbidden):
			writeError(w, badRequest("a wrapped key named someone who is not a member of this household"))
		case errors.Is(err, store.ErrNotFound):
			writeError(w, errNotFound("no money household here"))
		default:
			writeError(w, err)
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"granted": granted, "keyEpoch": req.KeyEpoch})
}

func (s *Server) handleListInvites(w http.ResponseWriter, r *http.Request) {
	invites, err := s.store.ListMoneyInvites(r.Context(), spaceIDFrom(r))
	if err != nil {
		writeError(w, err)
		return
	}
	out := make([]map[string]any, 0, len(invites))
	for _, i := range invites {
		out = append(out, map[string]any{"id": i.ID, "email": i.Email, "role": i.Role, "invitedBy": i.InvitedBy, "expiresAt": i.ExpiresAt, "createdAt": i.CreatedAt})
	}
	writeJSON(w, http.StatusOK, map[string]any{"invites": out})
}

// handleCreateInvite mints a household invitation.
//
// The plaintext token is returned once and never again: only its SHA-256 lands
// in the database, so a dump of money_invites yields no working invite links.
// Redeeming one makes the caller a member, which is permission to be handed the
// space key and not the key itself — see handleGrantKeys.
func (s *Server) handleCreateInvite(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if err := decodeJSON(w, r, maxSmallBody, &body); err != nil {
		writeError(w, err)
		return
	}
	email := strings.ToLower(strings.TrimSpace(body.Email))
	if !strings.Contains(email, "@") || len(email) < 3 || len(email) > 254 {
		writeError(w, badRequest("email must be a valid address"))
		return
	}
	if body.Role == "" {
		body.Role = "editor"
	}
	if !oneOf(body.Role, "editor", "viewer") {
		writeError(w, badRequest("role must be editor or viewer"))
		return
	}

	token, hash, err := mintInviteToken()
	if err != nil {
		writeError(w, err)
		return
	}

	invite, err := s.store.CreateMoneyInvite(r.Context(), spaceIDFrom(r), email, body.Role, hash, callerFrom(r.Context()).UserID, time.Now().UTC().Add(inviteTTL))
	if err != nil {
		writeError(w, storeError(err, "no money household here", "invite_exists", "that address already has an open invite to this household", "", ""))
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"id": invite.ID, "email": invite.Email, "role": invite.Role, "token": token, "expiresAt": invite.ExpiresAt})
}

// mintInviteToken generates an invite secret and the hash stored for it.
// Returns: the plaintext token to put in the link, its SHA-256, error
func mintInviteToken() (string, []byte, error) {
	raw := make([]byte, inviteTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("mint invite token: %w", err)
	}
	token := "oski_" + base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	return token, sum[:], nil
}

// handleRevokeInvite withdraws an outstanding invitation.
func (s *Server) handleRevokeInvite(w http.ResponseWriter, r *http.Request) {
	inviteID, err := parseUUIDParam(chi.URLParam(r, "inviteID"), "inviteId")
	if err != nil {
		writeError(w, err)
		return
	}
	if err := s.store.RevokeMoneyInvite(r.Context(), spaceIDFrom(r), inviteID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleAcceptInvite redeems an invitation token and joins the household.
//
// It is mounted outside the space router because the caller is by definition not
// yet a member, so no space-scoped middleware could authorize them. The response
// says plainly that the ledger is still locked: the invitee holds a membership
// and no key until an owner wraps one for their devices.
func (s *Server) handleAcceptInvite(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	if err := decodeJSON(w, r, maxSmallBody, &body); err != nil {
		writeError(w, err)
		return
	}
	token := strings.TrimSpace(body.Token)
	if !strings.HasPrefix(token, "oski_") {
		writeError(w, errNotFound("that invite is no longer valid"))
		return
	}

	sum := sha256.Sum256([]byte(token))
	spaceID, err := s.store.AcceptMoneyInvite(r.Context(), sum[:], callerFrom(r.Context()).UserID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, errNotFound("that invite is no longer valid"))
			return
		}
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"spaceId": spaceID, "awaitingKey": true})
}
