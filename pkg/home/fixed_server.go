package home

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
)

const (
	maxFixedName     = 60
	maxFixedNote     = 200
	maxProofBytes    = 6 << 20
	maxProofFileSize = 4 << 20
)

var fixedKinds = set("expense", "income", "investment")
var proofMediaTypes = set("image/jpeg", "image/png", "image/webp", "application/pdf")
var monthRule = regexp.MustCompile(`^\d{4}-(0[1-9]|1[0-2])$`)

// isProofPath picks out PUT /v1/fixed/{id}/payments/{month}/proof, which carries a file and so gets the large body
// limit and the long timeout the photo scan has.
func isProofPath(path string) bool {
	return strings.HasPrefix(path, "/v1/fixed/") && strings.HasSuffix(path, "/proof")
}

type fixedItemBody struct {
	Name        string     `json:"name"`
	Kind        string     `json:"kind"`
	AmountMinor int64      `json:"amountMinor"`
	OwnerID     *uuid.UUID `json:"ownerId"`
	CategoryID  *uuid.UUID `json:"categoryId"`
	DueDay      *int       `json:"dueDay"`
	StartsOn    string     `json:"startsOn"`
}

// validate checks one fixed item. Income needs an owner (a salary is somebody's); only an expense carries a category.
func (b fixedItemBody) validate() (FixedItem, error) {
	name := strings.Join(strings.Fields(b.Name), " ")
	switch {
	case !textBetween(name, 1, maxFixedName):
		return FixedItem{}, badRequest(fmt.Sprintf("name must be 1 to %d characters", maxFixedName))
	case !fixedKinds[b.Kind]:
		return FixedItem{}, badRequest("kind must be expense, income or investment")
	case b.AmountMinor <= 0 || b.AmountMinor > maxAmountMinor:
		return FixedItem{}, badRequest("amount must be above zero")
	case b.Kind == "income" && b.OwnerID == nil:
		return FixedItem{}, badRequest("income needs an owner")
	case b.Kind != "expense" && b.CategoryID != nil:
		return FixedItem{}, badRequest("only an expense has a category")
	case b.DueDay != nil && (*b.DueDay < 1 || *b.DueDay > 31):
		return FixedItem{}, badRequest("due day must be 1 to 31")
	case !monthRule.MatchString(b.StartsOn):
		return FixedItem{}, badRequest("startsOn must be YYYY-MM")
	}
	return FixedItem{Name: name, Kind: b.Kind, AmountMinor: b.AmountMinor, OwnerID: b.OwnerID, CategoryID: b.CategoryID, DueDay: b.DueDay, StartsOn: b.StartsOn}, nil
}

// listFixed answers Insights and Budgets: ?month=YYYY-MM, or ?from=YYYY-MM&to=YYYY-MM for up to 13 months.
func (s *Server) listFixed(w http.ResponseWriter, r *http.Request) {
	from, to := r.URL.Query().Get("from"), r.URL.Query().Get("to")
	if month := r.URL.Query().Get("month"); month != "" {
		from, to = month, month
	}
	if !monthRule.MatchString(from) || !monthRule.MatchString(to) {
		writeError(w, r, badRequest("month, or from and to, must be YYYY-MM"))
		return
	}
	months, err := s.store.FixedMonths(r.Context(), from, to)
	if errors.Is(err, ErrInvalid) {
		writeError(w, r, badRequest("from must not be after to, and the range at most 13 months"))
		return
	}
	if err != nil {
		writeError(w, r, err)
		return
	}
	sip, err := s.store.HoldingsSipMinor(r.Context())
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"months": months, "holdingsSipMinor": sip})
}

func (s *Server) createFixed(w http.ResponseWriter, r *http.Request) {
	s.writeFixed(w, r, nil, http.StatusCreated)
}

func (s *Server) replaceFixed(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, r, errNotFound)
		return
	}
	s.writeFixed(w, r, &id, http.StatusOK)
}

func (s *Server) writeFixed(w http.ResponseWriter, r *http.Request, id *uuid.UUID, status int) {
	var body fixedItemBody
	if err := decode(r, &body); err != nil {
		writeError(w, r, err)
		return
	}
	item, err := body.validate()
	if err != nil {
		writeError(w, r, err)
		return
	}
	saved, err := s.store.SaveFixedItem(r.Context(), id, item, actor(r).ID)
	if errors.Is(err, ErrInvalid) {
		writeError(w, r, badRequest("the owner must be a member and the category an expense category"))
		return
	}
	if err != nil {
		writeError(w, r, err)
		return
	}
	log.Printf("[%s] fixed item %s saved", middleware.GetReqID(r.Context()), saved.ID)
	writeJSON(w, status, saved)
}

// removeFixed archives an item from ?month=YYYY-MM (default: this month, UTC), keeping the months already paid.
func (s *Server) removeFixed(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, r, errNotFound)
		return
	}
	month := r.URL.Query().Get("month")
	if month == "" {
		month = time.Now().UTC().Format("2006-01")
	}
	if !monthRule.MatchString(month) {
		writeError(w, r, badRequest("month must be YYYY-MM"))
		return
	}
	if err := s.store.ArchiveFixedItem(r.Context(), id, month); err != nil {
		writeError(w, r, err)
		return
	}
	log.Printf("[%s] fixed item %s archived from %s", middleware.GetReqID(r.Context()), id, month)
	w.WriteHeader(http.StatusNoContent)
}

type fixedPaymentBody struct {
	AmountMinor int64      `json:"amountMinor"`
	PaidOn      string     `json:"paidOn"`
	PaidBy      *uuid.UUID `json:"paidBy"`
	Note        string     `json:"note"`
}

// paymentKey reads the item id and month from the path, answering 404 for a bad id and 400 for a bad month.
func paymentKey(w http.ResponseWriter, r *http.Request) (uuid.UUID, string, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, r, errNotFound)
		return uuid.UUID{}, "", false
	}
	month := chi.URLParam(r, "month")
	if !monthRule.MatchString(month) {
		writeError(w, r, badRequest("month must be YYYY-MM"))
		return uuid.UUID{}, "", false
	}
	return id, month, true
}

// tickFixed marks one month paid: PUT /v1/fixed/{id}/payments/{month}. A missing amount means the item's own;
// a missing date means today (UTC); a missing payer means the person ticking.
func (s *Server) tickFixed(w http.ResponseWriter, r *http.Request) {
	id, month, ok := paymentKey(w, r)
	if !ok {
		return
	}
	var body fixedPaymentBody
	if err := decode(r, &body); err != nil {
		writeError(w, r, err)
		return
	}
	note := strings.TrimSpace(body.Note)
	paidOn := body.PaidOn
	if paidOn == "" {
		paidOn = time.Now().UTC().Format("2006-01-02")
	}
	paidBy := body.PaidBy
	if paidBy == nil {
		me := actor(r).ID
		paidBy = &me
	}
	switch {
	case body.AmountMinor < 0 || body.AmountMinor > maxAmountMinor:
		writeError(w, r, badRequest("amount must be above zero"))
		return
	case !validDate(paidOn):
		writeError(w, r, badRequest("paidOn must be YYYY-MM-DD"))
		return
	case !textBetween(note, 0, maxFixedNote):
		writeError(w, r, badRequest(fmt.Sprintf("note must be at most %d characters", maxFixedNote)))
		return
	}
	saved, err := s.store.SaveFixedPayment(r.Context(), id, month, FixedPayment{AmountMinor: body.AmountMinor, PaidOn: paidOn, PaidBy: paidBy, Note: note})
	if errors.Is(err, ErrInvalid) {
		writeError(w, r, badRequest("paidBy must be a member"))
		return
	}
	if err != nil {
		writeError(w, r, err)
		return
	}
	log.Printf("[%s] fixed item %s ticked for %s", middleware.GetReqID(r.Context()), id, month)
	writeJSON(w, http.StatusOK, saved)
}

func (s *Server) untickFixed(w http.ResponseWriter, r *http.Request) {
	id, month, ok := paymentKey(w, r)
	if !ok {
		return
	}
	if err := s.store.RemoveFixedPayment(r.Context(), id, month); err != nil {
		writeError(w, r, err)
		return
	}
	log.Printf("[%s] fixed item %s unticked for %s", middleware.GetReqID(r.Context()), id, month)
	w.WriteHeader(http.StatusNoContent)
}

type proofBody struct {
	MediaType string `json:"mediaType"`
	Data      string `json:"data"`
}

// putProof attaches a bill or receipt (jpeg, png, webp or pdf, at most 4 MB) to a ticked month.
func (s *Server) putProof(w http.ResponseWriter, r *http.Request) {
	id, month, ok := paymentKey(w, r)
	if !ok {
		return
	}
	var body proofBody
	if err := decode(r, &body); err != nil {
		writeError(w, r, err)
		return
	}
	if !proofMediaTypes[body.MediaType] {
		writeError(w, r, badRequest("mediaType must be image/jpeg, image/png, image/webp or application/pdf"))
		return
	}
	raw, err := base64.StdEncoding.DecodeString(body.Data)
	if err != nil || len(raw) == 0 || len(raw) > maxProofFileSize {
		writeError(w, r, badRequest("data must be base64 and at most 4 MB"))
		return
	}
	if err := s.store.SaveFixedProof(r.Context(), id, month, FixedProof{MediaType: body.MediaType, Bytes: raw}); err != nil {
		writeError(w, r, err)
		return
	}
	log.Printf("[%s] proof saved on fixed item %s for %s: %s, %d bytes", middleware.GetReqID(r.Context()), id, month, body.MediaType, len(raw))
	w.WriteHeader(http.StatusNoContent)
}

// getProof streams the attachment back to the signed-in household, never cached by anything in between.
func (s *Server) getProof(w http.ResponseWriter, r *http.Request) {
	id, month, ok := paymentKey(w, r)
	if !ok {
		return
	}
	proof, err := s.store.FixedProof(r.Context(), id, month)
	if err != nil {
		writeError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", proof.MediaType)
	w.Header().Set("Content-Length", strconv.Itoa(len(proof.Bytes)))
	w.Header().Set("Content-Disposition", "inline")
	w.Header().Set("Cache-Control", "private, max-age=0")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(proof.Bytes)
}

func (s *Server) removeProof(w http.ResponseWriter, r *http.Request) {
	id, month, ok := paymentKey(w, r)
	if !ok {
		return
	}
	if err := s.store.RemoveFixedProof(r.Context(), id, month); err != nil {
		writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
