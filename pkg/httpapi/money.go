package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/ownspce/backend/pkg/ratelimit"
	"github.com/ownspce/backend/pkg/store"
)

// The money surface is the readable half of Ownspce.
//
// Every other data route in this file's siblings moves ciphertext. These move
// amounts, category names and notes in the clear, because budgets, settlement
// and portfolio valuation are arithmetic the server has to perform. What that
// costs is written down in pkg/store/money.go and in the README rather than
// left for a reader to infer from the absence of a seal.
//
// One consequence shows up here: money routes are mounted under requireAuth but
// NOT under requireActiveDevice. Device approval exists to gate the delivery of
// wrapped space keys, and a money row needs no key to read, so demanding it
// would lock a returning user out of their ledger the first time they open the
// web app while buying no confidentiality the database does not already lack.

// dateFormat is the wire format for every money date. Entries carry a calendar
// date, never a timestamp: a dinner logged in Bengaluru belongs to the day the
// household says it happened, and must not slide when a member opens the app
// from another timezone.
const dateFormat = "2006-01-02"

// inviteTokenBytes is the entropy behind a household invite link.
const inviteTokenBytes = 32

// inviteTTL bounds how long an emailed invitation stays redeemable.
const inviteTTL = 14 * 24 * time.Hour

// unitsPattern bounds an investment holding's unit count: up to eighteen whole
// digits and six decimal places, matching the numeric(24,6) column. Units are
// carried as a decimal string end to end so no float ever rounds a position.
var unitsPattern = regexp.MustCompile(`^\d{1,18}(\.\d{1,6})?$`)

// colorPattern matches the six-digit hex the category palette uses.
var colorPattern = regexp.MustCompile(`^#[0-9A-Fa-f]{6}$`)

// moneyRoutes mounts the whole money surface. It is called from routes() so the
// wiring is one line there and every handler below stays in this file.
//
// The tree hangs off /money rather than extending /spaces/{spaceID}, because
// chi mounts a subrouter over an entire subtree: adding /spaces/{spaceID}/money
// alongside the existing /spaces/{spaceID} router would be a second Mount on the
// same node and panic at startup. Keeping money on its own prefix also keeps the
// readable surface visibly separate from the sealed one in the route table.
func (s *Server) moneyRoutes(r chi.Router) {
	r.Route("/money", func(r chi.Router) {
		r.With(s.rateLimit(ratelimit.MoneyRead, subjectUser)).Get("/households", s.handleListHouseholds)
		r.With(s.rateLimit(ratelimit.MoneyWrite, subjectUser)).Post("/households", s.handleCreateHousehold)
		r.With(s.rateLimit(ratelimit.MoneyWrite, subjectUser)).Post("/invites/accept", s.handleAcceptInvite)

		r.Route("/households/{spaceID}", func(r chi.Router) {
			r.With(s.requireSpaceRole(store.RoleOwner), s.rateLimit(ratelimit.MoneyWrite, subjectUser)).Post("/enable", s.handleEnableMoney)

			r.Group(func(r chi.Router) {
				r.Use(s.requireMoneyRole(store.RoleViewer), s.rateLimit(ratelimit.MoneyRead, subjectUser))
				r.Get("/settings", s.handleGetMoneySettings)
				r.Get("/categories", s.handleListCategories)
				r.Get("/accounts", s.handleListAccounts)
				r.Get("/transactions", s.handleListTransactions)
				r.Get("/summary", s.handleMoneySummary)
				r.Get("/budgets", s.handleListBudgets)
				r.Get("/bills", s.handleListBills)
				r.Get("/holdings", s.handleListHoldings)
			})

			r.Group(func(r chi.Router) {
				r.Use(s.requireMoneyRole(store.RoleEditor), s.rateLimit(ratelimit.MoneyWrite, subjectUser))
				r.Post("/categories", s.handleCreateCategory)
				r.Patch("/categories/{categoryID}", s.handleUpdateCategory)
				r.Post("/accounts", s.handleCreateAccount)
				r.Patch("/accounts/{accountID}", s.handleUpdateAccount)
				r.Post("/transactions", s.handleCreateTransaction)
				r.Patch("/transactions/{transactionID}", s.handleUpdateTransaction)
				r.Delete("/transactions/{transactionID}", s.handleDeleteTransaction)
				r.Put("/budgets", s.handleUpsertBudget)
				r.Delete("/budgets/{budgetID}", s.handleDeleteBudget)
				r.Post("/bills", s.handleCreateBill)
				r.Patch("/bills/{billID}", s.handleUpdateBill)
				r.Post("/holdings", s.handleCreateHolding)
				r.Patch("/holdings/{holdingID}", s.handleUpdateHolding)
			})

			r.Group(func(r chi.Router) {
				r.Use(s.requireMoneyRole(store.RoleOwner))
				r.With(s.rateLimit(ratelimit.MoneyWrite, subjectUser)).Patch("/settings", s.handleUpdateMoneySettings)
				r.With(s.rateLimit(ratelimit.MoneyRead, subjectUser)).Get("/invites", s.handleListInvites)
				r.With(s.rateLimit(ratelimit.MoneyInvite, subjectUser)).Post("/invites", s.handleCreateInvite)
				r.With(s.rateLimit(ratelimit.MoneyWrite, subjectUser)).Delete("/invites/{inviteID}", s.handleRevokeInvite)
			})
		})
	})
}

// requireMoneyRole authorizes a money route, resolving membership and the
// money-enabled flag in a single query and putting the role in the context.
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

// spaceIDFrom re-reads the path parameter the money middleware already parsed.
func spaceIDFrom(r *http.Request) uuid.UUID {
	id, _ := uuid.Parse(chi.URLParam(r, "spaceID"))
	return id
}

// parseDate reads a required yyyy-mm-dd query parameter.
// Args: raw, field (name used in the error message)
// Returns: the parsed date, error
func parseDate(raw, field string) (time.Time, error) {
	parsed, err := time.Parse(dateFormat, strings.TrimSpace(raw))
	if err != nil {
		return time.Time{}, badRequest("%s must be a %s date", field, dateFormat)
	}
	return parsed, nil
}

// parsePeriod reads the from/to window every ledger read is scoped by.
//
// The window is required rather than defaulted: a missing bound would silently
// scan a household's whole history and return a figure the caller did not ask
// for, which on a spending total is worse than an error.
// Args: r (request carrying from and to query parameters)
// Returns: from, to, error
// Handles: a reversed window, rejected rather than quietly swapped
func parsePeriod(r *http.Request) (time.Time, time.Time, error) {
	from, err := parseDate(r.URL.Query().Get("from"), "from")
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	to, err := parseDate(r.URL.Query().Get("to"), "to")
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	if to.Before(from) {
		return time.Time{}, time.Time{}, badRequest("to must not be earlier than from")
	}
	return from, to, nil
}

// scopeFilter turns the mine/household toggle into a payer filter.
//
// "mine" means entries this member paid for, matching what the toggle says on
// screen. It is not a privacy boundary: a household member can always widen the
// toggle back out, and the role check above is what actually gates access.
// Args: r, callerID
// Returns: the payer to filter on, or nil for the whole household
// Handles: an unrecognised scope, which is rejected rather than silently
// treated as household
func scopeFilter(r *http.Request, callerID uuid.UUID) (*uuid.UUID, error) {
	switch scope := r.URL.Query().Get("scope"); scope {
	case "", "household":
		return nil, nil
	case "mine":
		return &callerID, nil
	default:
		return nil, badRequest("scope must be mine or household")
	}
}

// money renders an amount for the wire: an integer count of minor units plus the
// currency it is counted in. No decimal ever crosses the boundary, so no client
// can reintroduce a rounding error the server was careful to avoid.
func money(minor int64, currency string) map[string]any {
	return map[string]any{"minor": minor, "currency": currency}
}

func categoryJSON(c store.MoneyCategory) map[string]any {
	return map[string]any{"id": c.ID, "name": c.Name, "emoji": c.Emoji, "color": c.Color, "kind": c.Kind, "sortOrder": c.SortOrder, "archived": c.ArchivedAt != nil}
}

func accountJSON(a store.MoneyAccount) map[string]any {
	return map[string]any{"id": a.ID, "name": a.Name, "kind": a.Kind, "currency": a.Currency, "openingBalance": money(a.OpeningBalanceMinor, a.Currency), "isShared": a.IsShared, "ownerId": a.OwnerID, "archived": a.ArchivedAt != nil}
}

func transactionJSON(t store.MoneyTransaction) map[string]any {
	return map[string]any{"id": t.ID, "clientId": t.ClientID, "accountId": t.AccountID, "categoryId": t.CategoryID, "type": t.Type, "amount": money(t.AmountMinor, t.Currency), "occurredOn": t.OccurredOn.Format(dateFormat), "note": t.Note, "isShared": t.IsShared, "paidBy": t.PaidBy, "createdBy": t.CreatedBy, "createdAt": t.CreatedAt, "updatedAt": t.UpdatedAt}
}

func billJSON(b store.MoneyBill, currency string) map[string]any {
	var lastLogged any
	if b.LastLoggedOn != nil {
		lastLogged = b.LastLoggedOn.Format(dateFormat)
	}
	return map[string]any{"id": b.ID, "name": b.Name, "emoji": b.Emoji, "categoryId": b.CategoryID, "accountId": b.AccountID, "amount": money(b.AmountMinor, currency), "dayOfMonth": b.DayOfMonth, "autoLog": b.AutoLog, "isShared": b.IsShared, "paidBy": b.PaidBy, "lastLoggedOn": lastLogged}
}

// holdingJSON values a position exactly.
//
// units × price is computed with big.Rat rather than float64 and rounded once,
// at the end, to whole minor units. A large retirement balance times a six-place
// unit count exceeds the range where float64 is exact, and a portfolio that
// disagrees with the sum of its rows by a rupee is a support ticket.
func holdingJSON(h store.MoneyHolding) map[string]any {
	units, ok := new(big.Rat).SetString(h.Units)
	if !ok {
		units = new(big.Rat)
	}
	value := roundRatToMinor(new(big.Rat).Mul(units, new(big.Rat).SetInt64(h.LastPriceMinor)))
	cost := roundRatToMinor(new(big.Rat).Mul(units, new(big.Rat).SetInt64(h.AvgCostMinor)))
	return map[string]any{
		"id": h.ID, "ownerId": h.OwnerID, "name": h.Name, "badge": h.Badge, "assetType": h.AssetType,
		"units": h.Units, "avgCost": money(h.AvgCostMinor, h.Currency), "lastPrice": money(h.LastPriceMinor, h.Currency),
		"value": money(value, h.Currency), "cost": money(cost, h.Currency), "unrealised": money(value-cost, h.Currency),
		"dayChangeBps": h.DayChangeBps, "sip": money(h.SIPMinor, h.Currency), "color": h.Color, "pricedAt": h.PricedAt,
	}
}

// roundRatToMinor rounds an exact rational to the nearest whole minor unit,
// halves away from zero — the rule a person doing the same sum by hand uses.
func roundRatToMinor(r *big.Rat) int64 {
	num := new(big.Int).Set(r.Num())
	den := new(big.Int).Set(r.Denom())
	negative := num.Sign() < 0
	num.Abs(num)

	quotient, remainder := new(big.Int).QuoRem(num, den, new(big.Int))
	if new(big.Int).Lsh(remainder, 1).Cmp(den) >= 0 {
		quotient.Add(quotient, big.NewInt(1))
	}
	if negative {
		quotient.Neg(quotient)
	}
	if !quotient.IsInt64() {
		if negative {
			return -1 << 62
		}
		return 1 << 62
	}
	return quotient.Int64()
}

// handleListHouseholds lists every money-enabled household the caller belongs to.
func (s *Server) handleListHouseholds(w http.ResponseWriter, r *http.Request) {
	households, err := s.store.ListMoneyHouseholds(r.Context(), callerFrom(r.Context()).UserID)
	if err != nil {
		writeError(w, err)
		return
	}
	out := make([]map[string]any, 0, len(households))
	for _, h := range households {
		out = append(out, map[string]any{"spaceId": h.SpaceID, "role": h.Role, "memberCount": h.MemberCount, "currency": h.Settings.Currency, "locale": h.Settings.Locale, "sharedByDefault": h.Settings.SharedByDefault, "approvalThreshold": money(h.Settings.ApprovalThresholdMinor, h.Settings.Currency), "monthlyCloseDay": h.Settings.MonthlyCloseDay})
	}
	writeJSON(w, http.StatusOK, map[string]any{"households": out})
}

// handleCreateHousehold starts a brand-new household in one call.
//
// It exists so a first-time web session can get to a working ledger without
// going through space creation's key-wrapping ceremony, which protects content
// this space will never hold. Enabling money on a space the user already has
// remains available at POST /money/households/{spaceID}/enable.
func (s *Server) handleCreateHousehold(w http.ResponseWriter, r *http.Request) {
	spaceID, err := s.store.CreateMoneyHousehold(r.Context(), callerFrom(r.Context()).UserID)
	if err != nil {
		writeError(w, err)
		return
	}
	settings, err := s.store.MoneySettingsFor(r.Context(), spaceID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"spaceId": spaceID, "role": store.RoleOwner, "memberCount": 1, "currency": settings.Currency, "locale": settings.Locale, "sharedByDefault": settings.SharedByDefault, "approvalThreshold": money(settings.ApprovalThresholdMinor, settings.Currency), "monthlyCloseDay": settings.MonthlyCloseDay})
}

// handleEnableMoney turns an existing space into a money household.
//
// It deliberately reuses the space the user already has rather than minting a
// private one: membership, roles and removal are solved there, and a household
// that shares notes and a ledger should be one thing to leave, not two.
func (s *Server) handleEnableMoney(w http.ResponseWriter, r *http.Request) {
	settings, err := s.store.EnableMoney(r.Context(), spaceIDFrom(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, settingsJSON(settings))
}

func settingsJSON(m *store.MoneySettings) map[string]any {
	return map[string]any{"spaceId": m.SpaceID, "currency": m.Currency, "locale": m.Locale, "sharedByDefault": m.SharedByDefault, "approvalThreshold": money(m.ApprovalThresholdMinor, m.Currency), "monthlyCloseDay": m.MonthlyCloseDay, "updatedAt": m.UpdatedAt}
}

// handleGetMoneySettings returns one household's configuration.
func (s *Server) handleGetMoneySettings(w http.ResponseWriter, r *http.Request) {
	settings, err := s.store.MoneySettingsFor(r.Context(), spaceIDFrom(r))
	if err != nil {
		writeError(w, storeError(err, "no money household here", "", "", "", ""))
		return
	}
	writeJSON(w, http.StatusOK, settingsJSON(settings))
}

// handleUpdateMoneySettings applies a partial settings update. Owner only.
func (s *Server) handleUpdateMoneySettings(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Currency          *string `json:"currency"`
		Locale            *string `json:"locale"`
		SharedByDefault   *bool   `json:"sharedByDefault"`
		ApprovalThreshold *int64  `json:"approvalThresholdMinor"`
		MonthlyCloseDay   *int    `json:"monthlyCloseDay"`
	}
	if err := decodeJSON(w, r, maxSmallBody, &body); err != nil {
		writeError(w, err)
		return
	}
	if body.Currency != nil {
		*body.Currency = strings.ToUpper(strings.TrimSpace(*body.Currency))
		if len(*body.Currency) != 3 {
			writeError(w, badRequest("currency must be a three-letter code"))
			return
		}
	}
	if body.ApprovalThreshold != nil && *body.ApprovalThreshold < 0 {
		writeError(w, badRequest("approvalThresholdMinor must not be negative"))
		return
	}
	if body.MonthlyCloseDay != nil && (*body.MonthlyCloseDay < 1 || *body.MonthlyCloseDay > 28) {
		writeError(w, badRequest("monthlyCloseDay must be between 1 and 28"))
		return
	}

	settings, err := s.store.UpdateMoneySettings(r.Context(), spaceIDFrom(r), body.Currency, body.Locale, body.SharedByDefault, body.ApprovalThreshold, body.MonthlyCloseDay)
	if err != nil {
		writeError(w, storeError(err, "no money household here", "", "", "", ""))
		return
	}
	writeJSON(w, http.StatusOK, settingsJSON(settings))
}

// handleListCategories returns the household's categories.
func (s *Server) handleListCategories(w http.ResponseWriter, r *http.Request) {
	categories, err := s.store.ListMoneyCategories(r.Context(), spaceIDFrom(r), r.URL.Query().Get("includeArchived") == "true")
	if err != nil {
		writeError(w, err)
		return
	}
	out := make([]map[string]any, 0, len(categories))
	for _, c := range categories {
		out = append(out, categoryJSON(c))
	}
	writeJSON(w, http.StatusOK, map[string]any{"categories": out})
}

// handleCreateCategory adds a category to the household.
func (s *Server) handleCreateCategory(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name      string `json:"name"`
		Emoji     string `json:"emoji"`
		Color     string `json:"color"`
		Kind      string `json:"kind"`
		SortOrder int    `json:"sortOrder"`
	}
	if err := decodeJSON(w, r, maxSmallBody, &body); err != nil {
		writeError(w, err)
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" || len(body.Name) > 40 {
		writeError(w, badRequest("name must be between 1 and 40 characters"))
		return
	}
	if body.Color == "" {
		body.Color = "#6E7BF1"
	}
	if !colorPattern.MatchString(body.Color) {
		writeError(w, badRequest("color must be a six-digit hex value like #5FAF9F"))
		return
	}
	if body.Kind == "" {
		body.Kind = "expense"
	}
	if !oneOf(body.Kind, "expense", "income") {
		writeError(w, badRequest("kind must be expense or income"))
		return
	}

	category, err := s.store.CreateMoneyCategory(r.Context(), spaceIDFrom(r), body.Name, body.Emoji, body.Color, body.Kind, body.SortOrder)
	if err != nil {
		writeError(w, storeError(err, "no such category", "category_exists", "a category with that name already exists here", "", ""))
		return
	}
	writeJSON(w, http.StatusCreated, categoryJSON(*category))
}

// handleUpdateCategory applies a partial category update.
func (s *Server) handleUpdateCategory(w http.ResponseWriter, r *http.Request) {
	categoryID, err := parseUUIDParam(chi.URLParam(r, "categoryID"), "categoryId")
	if err != nil {
		writeError(w, err)
		return
	}
	var body struct {
		Name      *string `json:"name"`
		Emoji     *string `json:"emoji"`
		Color     *string `json:"color"`
		SortOrder *int    `json:"sortOrder"`
		Archived  *bool   `json:"archived"`
	}
	if err := decodeJSON(w, r, maxSmallBody, &body); err != nil {
		writeError(w, err)
		return
	}
	if body.Name != nil {
		*body.Name = strings.TrimSpace(*body.Name)
		if *body.Name == "" || len(*body.Name) > 40 {
			writeError(w, badRequest("name must be between 1 and 40 characters"))
			return
		}
	}
	if body.Color != nil && !colorPattern.MatchString(*body.Color) {
		writeError(w, badRequest("color must be a six-digit hex value like #5FAF9F"))
		return
	}

	category, err := s.store.UpdateMoneyCategory(r.Context(), spaceIDFrom(r), categoryID, body.Name, body.Emoji, body.Color, body.SortOrder, body.Archived)
	if err != nil {
		writeError(w, storeError(err, "no such category", "category_exists", "a category with that name already exists here", "", ""))
		return
	}
	writeJSON(w, http.StatusOK, categoryJSON(*category))
}

// handleListAccounts returns the household's accounts.
func (s *Server) handleListAccounts(w http.ResponseWriter, r *http.Request) {
	accounts, err := s.store.ListMoneyAccounts(r.Context(), spaceIDFrom(r))
	if err != nil {
		writeError(w, err)
		return
	}
	out := make([]map[string]any, 0, len(accounts))
	for _, a := range accounts {
		out = append(out, accountJSON(a))
	}
	writeJSON(w, http.StatusOK, map[string]any{"accounts": out})
}

// handleCreateAccount adds an account to the household.
func (s *Server) handleCreateAccount(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name           string `json:"name"`
		Kind           string `json:"kind"`
		Currency       string `json:"currency"`
		OpeningBalance int64  `json:"openingBalanceMinor"`
		IsShared       *bool  `json:"isShared"`
	}
	if err := decodeJSON(w, r, maxSmallBody, &body); err != nil {
		writeError(w, err)
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" || len(body.Name) > 80 {
		writeError(w, badRequest("name must be between 1 and 80 characters"))
		return
	}
	if body.Kind == "" {
		body.Kind = "bank"
	}
	if !oneOf(body.Kind, "bank", "cash", "card", "wallet", "loan", "investment") {
		writeError(w, badRequest("kind must be one of bank, cash, card, wallet, loan, investment"))
		return
	}
	currency, err := s.householdCurrency(r, body.Currency)
	if err != nil {
		writeError(w, err)
		return
	}
	isShared := true
	if body.IsShared != nil {
		isShared = *body.IsShared
	}
	ownerID := callerFrom(r.Context()).UserID

	account, err := s.store.CreateMoneyAccount(r.Context(), spaceIDFrom(r), body.Name, body.Kind, currency, body.OpeningBalance, isShared, &ownerID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, accountJSON(*account))
}

// handleUpdateAccount applies a partial account update.
func (s *Server) handleUpdateAccount(w http.ResponseWriter, r *http.Request) {
	accountID, err := parseUUIDParam(chi.URLParam(r, "accountID"), "accountId")
	if err != nil {
		writeError(w, err)
		return
	}
	var body struct {
		Name           *string `json:"name"`
		Kind           *string `json:"kind"`
		OpeningBalance *int64  `json:"openingBalanceMinor"`
		IsShared       *bool   `json:"isShared"`
		Archived       *bool   `json:"archived"`
	}
	if err := decodeJSON(w, r, maxSmallBody, &body); err != nil {
		writeError(w, err)
		return
	}
	if body.Kind != nil && !oneOf(*body.Kind, "bank", "cash", "card", "wallet", "loan", "investment") {
		writeError(w, badRequest("kind must be one of bank, cash, card, wallet, loan, investment"))
		return
	}

	account, err := s.store.UpdateMoneyAccount(r.Context(), spaceIDFrom(r), accountID, body.Name, body.Kind, body.OpeningBalance, body.IsShared, body.Archived)
	if err != nil {
		writeError(w, storeError(err, "no such account", "", "", "", ""))
		return
	}
	writeJSON(w, http.StatusOK, accountJSON(*account))
}

// householdCurrency resolves the currency for a new row, defaulting to the
// household's own so a member never has to restate it.
// Args: r, requested (empty to take the household default)
// Returns: the three-letter code, error
func (s *Server) householdCurrency(r *http.Request, requested string) (string, error) {
	if code := strings.ToUpper(strings.TrimSpace(requested)); code != "" {
		if len(code) != 3 {
			return "", badRequest("currency must be a three-letter code")
		}
		return code, nil
	}
	settings, err := s.store.MoneySettingsFor(r.Context(), spaceIDFrom(r))
	if err != nil {
		return "", storeError(err, "no money household here", "", "", "", "")
	}
	return settings.Currency, nil
}

// handleListTransactions returns a page of the ledger feed.
func (s *Server) handleListTransactions(w http.ResponseWriter, r *http.Request) {
	from, to, err := parsePeriod(r)
	if err != nil {
		writeError(w, err)
		return
	}
	paidBy, err := scopeFilter(r, callerFrom(r.Context()).UserID)
	if err != nil {
		writeError(w, err)
		return
	}
	limit := 0
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			writeError(w, badRequest("limit must be a positive integer"))
			return
		}
		limit = parsed
	}

	transactions, next, err := s.store.ListMoneyTransactions(r.Context(), store.TransactionFilter{
		SpaceID: spaceIDFrom(r), From: &from, To: &to, Search: r.URL.Query().Get("search"), PaidBy: paidBy, Limit: limit, Cursor: r.URL.Query().Get("cursor"),
	})
	if err != nil {
		writeError(w, storeError(err, "no such household", "invalid_cursor", "that cursor is not readable; start the walk again", "", ""))
		return
	}
	out := make([]map[string]any, 0, len(transactions))
	for _, t := range transactions {
		out = append(out, transactionJSON(t))
	}
	writeJSON(w, http.StatusOK, map[string]any{"transactions": out, "nextCursor": next})
}

// handleCreateTransaction appends an entry to the ledger.
func (s *Server) handleCreateTransaction(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ClientID    string  `json:"clientId"`
		AccountID   *string `json:"accountId"`
		CategoryID  string  `json:"categoryId"`
		Type        string  `json:"type"`
		AmountMinor int64   `json:"amountMinor"`
		Currency    string  `json:"currency"`
		OccurredOn  string  `json:"occurredOn"`
		Note        string  `json:"note"`
		IsShared    *bool   `json:"isShared"`
		PaidBy      *string `json:"paidBy"`
	}
	if err := decodeJSON(w, r, maxSmallBody, &body); err != nil {
		writeError(w, err)
		return
	}

	clientID, err := uuid.Parse(strings.TrimSpace(body.ClientID))
	if err != nil {
		writeError(w, badRequest("clientId must be a uuid minted by the client, so a retry cannot log the entry twice"))
		return
	}
	categoryID, err := uuid.Parse(strings.TrimSpace(body.CategoryID))
	if err != nil {
		writeError(w, badRequest("categoryId must be a uuid"))
		return
	}
	if !oneOf(body.Type, "expense", "income") {
		writeError(w, badRequest("type must be expense or income"))
		return
	}
	if body.AmountMinor <= 0 || body.AmountMinor > store.MaxTransactionAmountMinor {
		writeError(w, badRequest("amountMinor must be between 1 and %d", store.MaxTransactionAmountMinor))
		return
	}
	occurredOn, err := parseDate(body.OccurredOn, "occurredOn")
	if err != nil {
		writeError(w, err)
		return
	}
	if len(body.Note) > 280 {
		writeError(w, badRequest("note must be 280 characters or fewer"))
		return
	}
	currency, err := s.householdCurrency(r, body.Currency)
	if err != nil {
		writeError(w, err)
		return
	}

	caller := callerFrom(r.Context()).UserID
	transaction := store.MoneyTransaction{
		SpaceID: spaceIDFrom(r), ClientID: clientID, CategoryID: categoryID, Type: body.Type,
		AmountMinor: body.AmountMinor, Currency: currency, OccurredOn: occurredOn,
		Note: strings.TrimSpace(body.Note), IsShared: true, PaidBy: &caller, CreatedBy: &caller,
	}
	if body.IsShared != nil {
		transaction.IsShared = *body.IsShared
	}
	if body.AccountID != nil {
		accountID, err := uuid.Parse(strings.TrimSpace(*body.AccountID))
		if err != nil {
			writeError(w, badRequest("accountId must be a uuid"))
			return
		}
		transaction.AccountID = &accountID
	}
	if body.PaidBy != nil {
		payer, err := s.resolveHouseholdMember(r, *body.PaidBy)
		if err != nil {
			writeError(w, err)
			return
		}
		transaction.PaidBy = payer
	}

	created, err := s.store.CreateMoneyTransaction(r.Context(), transaction)
	if err != nil {
		writeError(w, storeError(err, "no such category or account", "", "", "cross_household", "that category or account belongs to another household"))
		return
	}
	writeJSON(w, http.StatusCreated, transactionJSON(*created))
}

// resolveHouseholdMember validates that an entry is being attributed to somebody
// who actually belongs to this household.
//
// Without this a member could pin their own spending onto a stranger's user id,
// which would then appear in that household's settle-up column.
// Args: r, raw (the claimed payer's user id)
// Returns: the payer, error
func (s *Server) resolveHouseholdMember(r *http.Request, raw string) (*uuid.UUID, error) {
	payer, err := uuid.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, badRequest("paidBy must be a uuid")
	}
	if _, err := s.store.SpaceRole(r.Context(), spaceIDFrom(r), payer); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, badRequest("paidBy must be a member of this household")
		}
		return nil, err
	}
	return &payer, nil
}

// handleUpdateTransaction applies a partial update to a ledger entry.
func (s *Server) handleUpdateTransaction(w http.ResponseWriter, r *http.Request) {
	transactionID, err := parseUUIDParam(chi.URLParam(r, "transactionID"), "transactionId")
	if err != nil {
		writeError(w, err)
		return
	}
	var body struct {
		AccountID   *string `json:"accountId"`
		CategoryID  *string `json:"categoryId"`
		AmountMinor *int64  `json:"amountMinor"`
		OccurredOn  *string `json:"occurredOn"`
		Note        *string `json:"note"`
		IsShared    *bool   `json:"isShared"`
		PaidBy      *string `json:"paidBy"`
	}
	if err := decodeJSON(w, r, maxSmallBody, &body); err != nil {
		writeError(w, err)
		return
	}

	var categoryID, accountID, paidBy *uuid.UUID
	if body.CategoryID != nil {
		parsed, err := uuid.Parse(strings.TrimSpace(*body.CategoryID))
		if err != nil {
			writeError(w, badRequest("categoryId must be a uuid"))
			return
		}
		categoryID = &parsed
	}
	if body.AccountID != nil {
		parsed, err := uuid.Parse(strings.TrimSpace(*body.AccountID))
		if err != nil {
			writeError(w, badRequest("accountId must be a uuid"))
			return
		}
		accountID = &parsed
	}
	if body.PaidBy != nil {
		paidBy, err = s.resolveHouseholdMember(r, *body.PaidBy)
		if err != nil {
			writeError(w, err)
			return
		}
	}
	if body.AmountMinor != nil && (*body.AmountMinor <= 0 || *body.AmountMinor > store.MaxTransactionAmountMinor) {
		writeError(w, badRequest("amountMinor must be between 1 and %d", store.MaxTransactionAmountMinor))
		return
	}
	if body.Note != nil && len(*body.Note) > 280 {
		writeError(w, badRequest("note must be 280 characters or fewer"))
		return
	}
	var occurredOn *time.Time
	if body.OccurredOn != nil {
		parsed, err := parseDate(*body.OccurredOn, "occurredOn")
		if err != nil {
			writeError(w, err)
			return
		}
		occurredOn = &parsed
	}

	updated, err := s.store.UpdateMoneyTransaction(r.Context(), spaceIDFrom(r), transactionID, categoryID, accountID, body.AmountMinor, occurredOn, body.Note, body.IsShared, paidBy)
	if err != nil {
		writeError(w, storeError(err, "no such entry", "", "", "cross_household", "that category belongs to another household"))
		return
	}
	writeJSON(w, http.StatusOK, transactionJSON(*updated))
}

// handleDeleteTransaction soft-deletes a ledger entry.
func (s *Server) handleDeleteTransaction(w http.ResponseWriter, r *http.Request) {
	transactionID, err := parseUUIDParam(chi.URLParam(r, "transactionID"), "transactionId")
	if err != nil {
		writeError(w, err)
		return
	}
	if err := s.store.DeleteMoneyTransaction(r.Context(), spaceIDFrom(r), transactionID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleMoneySummary returns every aggregate the insights screen renders.
func (s *Server) handleMoneySummary(w http.ResponseWriter, r *http.Request) {
	from, to, err := parsePeriod(r)
	if err != nil {
		writeError(w, err)
		return
	}
	paidBy, err := scopeFilter(r, callerFrom(r.Context()).UserID)
	if err != nil {
		writeError(w, err)
		return
	}
	settings, err := s.store.MoneySettingsFor(r.Context(), spaceIDFrom(r))
	if err != nil {
		writeError(w, storeError(err, "no money household here", "", "", "", ""))
		return
	}

	summary, err := s.store.MoneySummaryFor(r.Context(), spaceIDFrom(r), from, to, paidBy)
	if err != nil {
		writeError(w, err)
		return
	}

	categories := make([]map[string]any, 0, len(summary.Categories))
	for _, c := range summary.Categories {
		categories = append(categories, map[string]any{"categoryId": c.CategoryID, "name": c.Name, "emoji": c.Emoji, "color": c.Color, "amount": money(c.AmountMinor, settings.Currency), "count": c.Count})
	}
	members := make([]map[string]any, 0, len(summary.Members))
	for _, m := range summary.Members {
		members = append(members, map[string]any{"userId": m.UserID, "name": m.Name, "spent": money(m.AmountMinor, settings.Currency), "sharedSpent": money(m.SharedSpentMinor, settings.Currency)})
	}
	days := make([]map[string]any, 0, len(summary.Days))
	for _, d := range summary.Days {
		days = append(days, map[string]any{"day": d.Day.Format(dateFormat), "amount": money(d.AmountMinor, settings.Currency)})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"from": from.Format(dateFormat), "to": to.Format(dateFormat), "currency": settings.Currency,
		"spent": money(summary.Totals.SpentMinor, settings.Currency), "income": money(summary.Totals.IncomeMinor, settings.Currency),
		"net": money(summary.Totals.IncomeMinor-summary.Totals.SpentMinor, settings.Currency), "count": summary.Totals.Count,
		"categories": categories, "members": members, "days": days,
	})
}

// handleListBudgets returns every budget with its usage over the given period.
func (s *Server) handleListBudgets(w http.ResponseWriter, r *http.Request) {
	from, to, err := parsePeriod(r)
	if err != nil {
		writeError(w, err)
		return
	}
	settings, err := s.store.MoneySettingsFor(r.Context(), spaceIDFrom(r))
	if err != nil {
		writeError(w, storeError(err, "no money household here", "", "", "", ""))
		return
	}

	budgets, err := s.store.ListMoneyBudgets(r.Context(), spaceIDFrom(r), from, to)
	if err != nil {
		writeError(w, err)
		return
	}
	out := make([]map[string]any, 0, len(budgets))
	for _, b := range budgets {
		out = append(out, map[string]any{"id": b.Budget.ID, "categoryId": b.Budget.CategoryID, "name": b.Name, "emoji": b.Emoji, "color": b.Color, "period": b.Budget.Period, "limit": money(b.Budget.LimitMinor, settings.Currency), "used": money(b.UsedMinor, settings.Currency), "remaining": money(b.Budget.LimitMinor-b.UsedMinor, settings.Currency)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"from": from.Format(dateFormat), "to": to.Format(dateFormat), "budgets": out})
}

// handleUpsertBudget sets the monthly ceiling for one category.
func (s *Server) handleUpsertBudget(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CategoryID string `json:"categoryId"`
		LimitMinor int64  `json:"limitMinor"`
	}
	if err := decodeJSON(w, r, maxSmallBody, &body); err != nil {
		writeError(w, err)
		return
	}
	categoryID, err := uuid.Parse(strings.TrimSpace(body.CategoryID))
	if err != nil {
		writeError(w, badRequest("categoryId must be a uuid"))
		return
	}
	if body.LimitMinor <= 0 || body.LimitMinor > store.MaxTransactionAmountMinor {
		writeError(w, badRequest("limitMinor must be between 1 and %d", store.MaxTransactionAmountMinor))
		return
	}

	budget, err := s.store.UpsertMoneyBudget(r.Context(), spaceIDFrom(r), categoryID, body.LimitMinor)
	if err != nil {
		writeError(w, storeError(err, "no such category", "", "", "cross_household", "that category belongs to another household"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": budget.ID, "categoryId": budget.CategoryID, "period": budget.Period, "limitMinor": budget.LimitMinor, "startsOn": budget.StartsOn.Format(dateFormat)})
}

// handleDeleteBudget removes a category ceiling.
func (s *Server) handleDeleteBudget(w http.ResponseWriter, r *http.Request) {
	budgetID, err := parseUUIDParam(chi.URLParam(r, "budgetID"), "budgetId")
	if err != nil {
		writeError(w, err)
		return
	}
	if err := s.store.DeleteMoneyBudget(r.Context(), spaceIDFrom(r), budgetID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleListBills returns the household's recurring charges.
func (s *Server) handleListBills(w http.ResponseWriter, r *http.Request) {
	settings, err := s.store.MoneySettingsFor(r.Context(), spaceIDFrom(r))
	if err != nil {
		writeError(w, storeError(err, "no money household here", "", "", "", ""))
		return
	}
	bills, err := s.store.ListMoneyBills(r.Context(), spaceIDFrom(r))
	if err != nil {
		writeError(w, err)
		return
	}
	out := make([]map[string]any, 0, len(bills))
	for _, b := range bills {
		out = append(out, billJSON(b, settings.Currency))
	}
	writeJSON(w, http.StatusOK, map[string]any{"bills": out})
}

// handleCreateBill adds a recurring charge.
func (s *Server) handleCreateBill(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name        string  `json:"name"`
		Emoji       string  `json:"emoji"`
		CategoryID  *string `json:"categoryId"`
		AccountID   *string `json:"accountId"`
		AmountMinor int64   `json:"amountMinor"`
		DayOfMonth  int     `json:"dayOfMonth"`
		AutoLog     bool    `json:"autoLog"`
		IsShared    *bool   `json:"isShared"`
	}
	if err := decodeJSON(w, r, maxSmallBody, &body); err != nil {
		writeError(w, err)
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" || len(body.Name) > 120 {
		writeError(w, badRequest("name must be between 1 and 120 characters"))
		return
	}
	if body.AmountMinor <= 0 || body.AmountMinor > store.MaxTransactionAmountMinor {
		writeError(w, badRequest("amountMinor must be between 1 and %d", store.MaxTransactionAmountMinor))
		return
	}
	if body.DayOfMonth < 1 || body.DayOfMonth > 28 {
		writeError(w, badRequest("dayOfMonth must be between 1 and 28, so a bill lands in every month"))
		return
	}

	caller := callerFrom(r.Context()).UserID
	bill := store.MoneyBill{SpaceID: spaceIDFrom(r), Name: body.Name, Emoji: body.Emoji, AmountMinor: body.AmountMinor, DayOfMonth: body.DayOfMonth, AutoLog: body.AutoLog, IsShared: true, PaidBy: &caller}
	if body.IsShared != nil {
		bill.IsShared = *body.IsShared
	}
	if body.CategoryID != nil {
		parsed, err := uuid.Parse(strings.TrimSpace(*body.CategoryID))
		if err != nil {
			writeError(w, badRequest("categoryId must be a uuid"))
			return
		}
		bill.CategoryID = &parsed
	}
	if body.AccountID != nil {
		parsed, err := uuid.Parse(strings.TrimSpace(*body.AccountID))
		if err != nil {
			writeError(w, badRequest("accountId must be a uuid"))
			return
		}
		bill.AccountID = &parsed
	}

	created, err := s.store.CreateMoneyBill(r.Context(), bill)
	if err != nil {
		writeError(w, err)
		return
	}
	settings, err := s.store.MoneySettingsFor(r.Context(), spaceIDFrom(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, billJSON(*created, settings.Currency))
}

// handleUpdateBill applies a partial update to a recurring charge.
func (s *Server) handleUpdateBill(w http.ResponseWriter, r *http.Request) {
	billID, err := parseUUIDParam(chi.URLParam(r, "billID"), "billId")
	if err != nil {
		writeError(w, err)
		return
	}
	var body struct {
		Name        *string `json:"name"`
		Emoji       *string `json:"emoji"`
		AmountMinor *int64  `json:"amountMinor"`
		DayOfMonth  *int    `json:"dayOfMonth"`
		AutoLog     *bool   `json:"autoLog"`
		Archived    *bool   `json:"archived"`
	}
	if err := decodeJSON(w, r, maxSmallBody, &body); err != nil {
		writeError(w, err)
		return
	}
	if body.AmountMinor != nil && (*body.AmountMinor <= 0 || *body.AmountMinor > store.MaxTransactionAmountMinor) {
		writeError(w, badRequest("amountMinor must be between 1 and %d", store.MaxTransactionAmountMinor))
		return
	}
	if body.DayOfMonth != nil && (*body.DayOfMonth < 1 || *body.DayOfMonth > 28) {
		writeError(w, badRequest("dayOfMonth must be between 1 and 28, so a bill lands in every month"))
		return
	}

	updated, err := s.store.UpdateMoneyBill(r.Context(), spaceIDFrom(r), billID, body.Name, body.Emoji, body.AmountMinor, body.DayOfMonth, body.AutoLog, body.Archived)
	if err != nil {
		writeError(w, storeError(err, "no such bill", "", "", "", ""))
		return
	}
	settings, err := s.store.MoneySettingsFor(r.Context(), spaceIDFrom(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, billJSON(*updated, settings.Currency))
}

// handleListHoldings returns the household's investment positions.
func (s *Server) handleListHoldings(w http.ResponseWriter, r *http.Request) {
	holdings, err := s.store.ListMoneyHoldings(r.Context(), spaceIDFrom(r))
	if err != nil {
		writeError(w, err)
		return
	}
	out := make([]map[string]any, 0, len(holdings))
	for _, h := range holdings {
		out = append(out, holdingJSON(h))
	}
	writeJSON(w, http.StatusOK, map[string]any{"holdings": out})
}

// handleCreateHolding adds an investment position.
func (s *Server) handleCreateHolding(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name           string  `json:"name"`
		Badge          string  `json:"badge"`
		AssetType      string  `json:"assetType"`
		Units          string  `json:"units"`
		AvgCostMinor   int64   `json:"avgCostMinor"`
		LastPriceMinor int64   `json:"lastPriceMinor"`
		DayChangeBps   int     `json:"dayChangeBps"`
		SIPMinor       int64   `json:"sipMinor"`
		Currency       string  `json:"currency"`
		Color          string  `json:"color"`
		OwnerID        *string `json:"ownerId"`
	}
	if err := decodeJSON(w, r, maxSmallBody, &body); err != nil {
		writeError(w, err)
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" || len(body.Name) > 120 {
		writeError(w, badRequest("name must be between 1 and 120 characters"))
		return
	}
	if len(body.Badge) > 8 {
		writeError(w, badRequest("badge must be 8 characters or fewer"))
		return
	}
	if body.AssetType == "" {
		body.AssetType = "other"
	}
	if !oneOf(body.AssetType, "mutual_fund", "stocks", "gold", "retirement", "debt", "cash", "other") {
		writeError(w, badRequest("assetType must be one of mutual_fund, stocks, gold, retirement, debt, cash, other"))
		return
	}
	if err := validateUnits(body.Units); err != nil {
		writeError(w, err)
		return
	}
	if body.AvgCostMinor < 0 || body.LastPriceMinor < 0 || body.SIPMinor < 0 {
		writeError(w, badRequest("avgCostMinor, lastPriceMinor and sipMinor must not be negative"))
		return
	}
	if body.Color == "" {
		body.Color = "#6E7BF1"
	}
	if !colorPattern.MatchString(body.Color) {
		writeError(w, badRequest("color must be a six-digit hex value like #279AF4"))
		return
	}
	currency, err := s.householdCurrency(r, body.Currency)
	if err != nil {
		writeError(w, err)
		return
	}

	owner := callerFrom(r.Context()).UserID
	holding := store.MoneyHolding{SpaceID: spaceIDFrom(r), OwnerID: &owner, Name: body.Name, Badge: body.Badge, AssetType: body.AssetType, Units: body.Units, AvgCostMinor: body.AvgCostMinor, LastPriceMinor: body.LastPriceMinor, DayChangeBps: body.DayChangeBps, SIPMinor: body.SIPMinor, Currency: currency, Color: body.Color}
	if body.OwnerID != nil {
		resolved, err := s.resolveHouseholdMember(r, *body.OwnerID)
		if err != nil {
			writeError(w, err)
			return
		}
		holding.OwnerID = resolved
	}

	created, err := s.store.CreateMoneyHolding(r.Context(), holding)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, holdingJSON(*created))
}

// validateUnits bounds a holding's unit count to what the numeric column holds.
func validateUnits(raw string) error {
	units := strings.TrimSpace(raw)
	if !unitsPattern.MatchString(units) {
		return badRequest("units must be a positive decimal with up to 6 decimal places")
	}
	if strings.Trim(strings.ReplaceAll(units, ".", ""), "0") == "" {
		return badRequest("units must be greater than zero")
	}
	return nil
}

// handleUpdateHolding applies a partial update to an investment position.
func (s *Server) handleUpdateHolding(w http.ResponseWriter, r *http.Request) {
	holdingID, err := parseUUIDParam(chi.URLParam(r, "holdingID"), "holdingId")
	if err != nil {
		writeError(w, err)
		return
	}
	var body struct {
		Units          *string `json:"units"`
		AvgCostMinor   *int64  `json:"avgCostMinor"`
		LastPriceMinor *int64  `json:"lastPriceMinor"`
		DayChangeBps   *int    `json:"dayChangeBps"`
		SIPMinor       *int64  `json:"sipMinor"`
		Archived       *bool   `json:"archived"`
	}
	if err := decodeJSON(w, r, maxSmallBody, &body); err != nil {
		writeError(w, err)
		return
	}
	if body.Units != nil {
		if err := validateUnits(*body.Units); err != nil {
			writeError(w, err)
			return
		}
	}
	if (body.AvgCostMinor != nil && *body.AvgCostMinor < 0) || (body.LastPriceMinor != nil && *body.LastPriceMinor < 0) || (body.SIPMinor != nil && *body.SIPMinor < 0) {
		writeError(w, badRequest("avgCostMinor, lastPriceMinor and sipMinor must not be negative"))
		return
	}

	updated, err := s.store.UpdateMoneyHolding(r.Context(), spaceIDFrom(r), holdingID, body.Units, body.AvgCostMinor, body.LastPriceMinor, body.DayChangeBps, body.SIPMinor, body.Archived)
	if err != nil {
		writeError(w, storeError(err, "no such holding", "", "", "", ""))
		return
	}
	writeJSON(w, http.StatusOK, holdingJSON(*updated))
}

// handleListInvites returns the household's outstanding invitations. Owner only,
// because the list is a set of email addresses of people not yet in the account.
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
// yet a member, so no space-scoped middleware could authorize them.
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
	writeJSON(w, http.StatusOK, map[string]any{"spaceId": spaceID})
}
