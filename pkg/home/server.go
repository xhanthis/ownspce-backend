package home

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

const (
	sessionTTL       = 90 * 24 * time.Hour
	maxBodyBytes     = 64 << 10
	requestTimeout   = 10 * time.Second
	maxAmountMinor   = 100_000_000_000
	loginWindow      = 15 * time.Minute
	loginFailures    = 10
	maxTrackedLogins = 1000
	MinPassword      = 8
)

var (
	isoDate      = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	hexColor     = regexp.MustCompile(`^#[0-9A-Fa-f]{6}$`)
	unitCount    = regexp.MustCompile(`^\d{1,18}(\.\d{1,6})?$`)
	usernameRule = regexp.MustCompile(`^[a-z0-9._-]{2,32}$`)
	themes       = set("system", "light", "dark")
	palettes     = set("cream", "paper", "sand", "graphite", "midnight", "indigo", "evergreen")
	fonts        = set("grotesk", "sans", "serif")
	entryTypes   = set("expense", "income")
	assetTypes   = set("stocks", "mutual_fund", "fd", "epf", "bank", "nps", "gold", "other")
	dummyHash, _ = bcrypt.GenerateFromPassword([]byte("home-timing-equaliser"), bcrypt.DefaultCost)
)

type apiError struct {
	status  int
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e apiError) Error() string { return e.Code + ": " + e.Message }

func badRequest(message string) apiError {
	return apiError{status: http.StatusBadRequest, Code: "invalid_request", Message: message}
}

var (
	errUnauthorized = apiError{status: http.StatusUnauthorized, Code: "unauthorized", Message: "sign in again"}
	errBadLogin     = apiError{status: http.StatusUnauthorized, Code: "bad_login", Message: "that username and password do not match"}
	errTooMany      = apiError{status: http.StatusTooManyRequests, Code: "too_many_attempts", Message: "too many attempts, wait a few minutes"}
	errNotFound     = apiError{status: http.StatusNotFound, Code: "not_found", Message: "not found"}
	errInternal     = apiError{status: http.StatusInternalServerError, Code: "internal", Message: "something went wrong"}
)

type ctxKey struct{}

type Server struct {
	store   *Store
	limiter *loginLimiter
}

// NewServer builds the HTTP handler for Home over an opened store.
// Args: store (from Open)
// Returns: a handler serving every route under /v1
func NewServer(store *Store) http.Handler {
	server := &Server{store: store, limiter: &loginLimiter{failures: map[string][]time.Time{}}}

	router := chi.NewRouter()
	router.Use(middleware.RequestID, middleware.Recoverer, middleware.Timeout(requestTimeout))
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
			next.ServeHTTP(w, r)
		})
	})

	router.Route("/v1", func(v1 chi.Router) {
		v1.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		})
		v1.Post("/auth/login", server.login)

		v1.Group(func(authed chi.Router) {
			authed.Use(server.authenticate)
			authed.Post("/auth/logout", server.logout)
			authed.Get("/me", server.me)
			authed.Patch("/me", server.updateMe)
			authed.Get("/home", server.home)
			authed.Patch("/settings", server.updateSettings)
			authed.Get("/entries", server.listEntries)
			authed.Post("/entries", server.createEntry)
			authed.Put("/entries/{id}", server.replaceEntry)
			authed.Delete("/entries/{id}", server.removeEntry)
			authed.Put("/budgets/{categoryId}", server.saveBudget)
			authed.Delete("/budgets/{categoryId}", server.removeBudget)
			authed.Post("/holdings", server.createHolding)
			authed.Put("/holdings/{id}", server.replaceHolding)
			authed.Delete("/holdings/{id}", server.removeHolding)
		})
	})
	return router
}

// HashPassword turns a password into the bcrypt hash the store keeps.
// Returns: an error when the password is shorter than MinPassword or longer than bcrypt accepts
func HashPassword(password string) (string, error) {
	if len(password) < MinPassword {
		return "", errors.New("password must be at least 8 characters")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// NormaliseUsername folds a typed username to its stored form and checks its shape.
// Returns: the stored form, or false when it is not 2–32 of a-z 0-9 . _ -
func NormaliseUsername(raw string) (string, bool) {
	username := strings.ToLower(strings.TrimSpace(raw))
	return username, usernameRule.MatchString(username)
}

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(r, &body); err != nil {
		writeError(w, r, err)
		return
	}
	username, ok := NormaliseUsername(body.Username)
	if !ok || body.Password == "" || len(body.Password) > 72 {
		writeError(w, r, errBadLogin)
		return
	}
	limitKey := username
	if !s.limiter.allow(limitKey) {
		writeError(w, r, errTooMany)
		return
	}

	user, err := s.store.UserByUsername(r.Context(), username)
	if errors.Is(err, ErrNotFound) {
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(body.Password))
		s.limiter.fail(limitKey)
		writeError(w, r, errBadLogin)
		return
	}
	if err != nil {
		writeError(w, r, err)
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(user.passwordHash), []byte(body.Password)) != nil {
		s.limiter.fail(limitKey)
		writeError(w, r, errBadLogin)
		return
	}
	s.limiter.clear(limitKey)

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		writeError(w, r, err)
		return
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	if err := s.store.CreateSession(r.Context(), tokenHash(token), user.ID, sessionTTL); err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "user": user})
}

func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !found || token == "" {
			writeError(w, r, errUnauthorized)
			return
		}
		user, err := s.store.UserBySession(r.Context(), tokenHash(token))
		if errors.Is(err, ErrNotFound) {
			writeError(w, r, errUnauthorized)
			return
		}
		if err != nil {
			writeError(w, r, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, user)))
	})
}

func actor(r *http.Request) User {
	user, _ := r.Context().Value(ctxKey{}).(User)
	return user
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if err := s.store.EndSession(r.Context(), tokenHash(token)); err != nil {
		writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, actor(r))
}

func (s *Server) updateMe(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name    *string `json:"name"`
		Theme   *string `json:"theme"`
		Palette *string `json:"palette"`
		Font    *string `json:"font"`
	}
	if err := decode(r, &body); err != nil {
		writeError(w, r, err)
		return
	}
	if body.Name != nil {
		trimmed := strings.TrimSpace(*body.Name)
		if !textBetween(trimmed, 1, 60) {
			writeError(w, r, badRequest("name must be 1 to 60 characters"))
			return
		}
		body.Name = &trimmed
	}
	if !oneOfOrNil(body.Theme, themes) || !oneOfOrNil(body.Palette, palettes) || !oneOfOrNil(body.Font, fonts) {
		writeError(w, r, badRequest("unknown appearance choice"))
		return
	}
	user, err := s.store.UpdateProfile(r.Context(), actor(r).ID, ProfilePatch{Name: body.Name, Theme: body.Theme, Palette: body.Palette, Font: body.Font})
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, user)
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	settings, err := s.store.Settings(ctx)
	if err != nil {
		writeError(w, r, err)
		return
	}
	members, err := s.store.Members(ctx)
	if err != nil {
		writeError(w, r, err)
		return
	}
	categories, err := s.store.Categories(ctx)
	if err != nil {
		writeError(w, r, err)
		return
	}
	budgets, err := s.store.Budgets(ctx)
	if err != nil {
		writeError(w, r, err)
		return
	}
	holdings, err := s.store.Holdings(ctx)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user":       actor(r),
		"settings":   settings,
		"members":    members,
		"categories": categories,
		"budgets":    budgets,
		"holdings":   holdings,
	})
}

type optionalAmount struct {
	set   bool
	value *int64
}

func (o *optionalAmount) UnmarshalJSON(raw []byte) error {
	o.set = true
	if string(raw) == "null" {
		o.value = nil
		return nil
	}
	var value int64
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	o.value = &value
	return nil
}

func (s *Server) updateSettings(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name               *string        `json:"name"`
		SharedByDefault    *bool          `json:"sharedByDefault"`
		IncomeTracking     *bool          `json:"incomeTracking"`
		OverallBudgetMinor optionalAmount `json:"overallBudgetMinor"`
	}
	if err := decode(r, &body); err != nil {
		writeError(w, r, err)
		return
	}
	if body.Name != nil {
		trimmed := strings.TrimSpace(*body.Name)
		if !textBetween(trimmed, 1, 60) {
			writeError(w, r, badRequest("household name must be 1 to 60 characters"))
			return
		}
		body.Name = &trimmed
	}
	if limit := body.OverallBudgetMinor.value; limit != nil && (*limit <= 0 || *limit > maxAmountMinor) {
		writeError(w, r, badRequest("overall budget must be a positive amount"))
		return
	}
	settings, err := s.store.UpdateSettings(r.Context(), SettingsPatch{
		Name:               body.Name,
		SharedByDefault:    body.SharedByDefault,
		IncomeTracking:     body.IncomeTracking,
		SetOverallBudget:   body.OverallBudgetMinor.set,
		OverallBudgetMinor: body.OverallBudgetMinor.value,
	})
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, settings)
}

func (s *Server) listEntries(w http.ResponseWriter, r *http.Request) {
	from, to := r.URL.Query().Get("from"), r.URL.Query().Get("to")
	if !validDate(from) || !validDate(to) || from > to {
		writeError(w, r, badRequest("from and to must be yyyy-mm-dd dates, from not after to"))
		return
	}
	entries, truncated, err := s.store.Entries(r.Context(), from, to)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries, "truncated": truncated})
}

type entryBody struct {
	OccurredOn  string     `json:"occurredOn"`
	Type        string     `json:"type"`
	AmountMinor int64      `json:"amountMinor"`
	CategoryID  uuid.UUID  `json:"categoryId"`
	Note        string     `json:"note"`
	IsShared    bool       `json:"isShared"`
	PaidBy      *uuid.UUID `json:"paidBy"`
}

func (b entryBody) validate() (Entry, error) {
	note := strings.TrimSpace(b.Note)
	switch {
	case !validDate(b.OccurredOn):
		return Entry{}, badRequest("occurredOn must be a yyyy-mm-dd date")
	case !entryTypes[b.Type]:
		return Entry{}, badRequest("type must be expense or income")
	case b.AmountMinor <= 0 || b.AmountMinor > maxAmountMinor:
		return Entry{}, badRequest("amount must be more than zero and at most 1,000,000,000")
	case b.CategoryID == uuid.Nil:
		return Entry{}, badRequest("pick a category")
	case !textBetween(note, 0, 200):
		return Entry{}, badRequest("note must be at most 200 characters")
	}
	return Entry{OccurredOn: b.OccurredOn, Type: b.Type, AmountMinor: b.AmountMinor, CategoryID: b.CategoryID, Note: note, IsShared: b.IsShared, PaidBy: b.PaidBy}, nil
}

func (s *Server) createEntry(w http.ResponseWriter, r *http.Request) {
	s.writeEntry(w, r, nil, http.StatusCreated)
}

func (s *Server) replaceEntry(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, r, errNotFound)
		return
	}
	s.writeEntry(w, r, &id, http.StatusOK)
}

func (s *Server) writeEntry(w http.ResponseWriter, r *http.Request, id *uuid.UUID, status int) {
	var body entryBody
	if err := decode(r, &body); err != nil {
		writeError(w, r, err)
		return
	}
	entry, err := body.validate()
	if err != nil {
		writeError(w, r, err)
		return
	}
	saved, err := s.store.SaveEntry(r.Context(), id, entry, actor(r).ID)
	if errors.Is(err, ErrInvalid) {
		writeError(w, r, badRequest("that category or payer does not exist here"))
		return
	}
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, status, saved)
}

func (s *Server) removeEntry(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, r, errNotFound)
		return
	}
	if err := s.store.RemoveEntry(r.Context(), id); err != nil {
		writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) saveBudget(w http.ResponseWriter, r *http.Request) {
	categoryID, err := uuid.Parse(chi.URLParam(r, "categoryId"))
	if err != nil {
		writeError(w, r, errNotFound)
		return
	}
	var body struct {
		LimitMinor int64 `json:"limitMinor"`
	}
	if err := decode(r, &body); err != nil {
		writeError(w, r, err)
		return
	}
	if body.LimitMinor <= 0 || body.LimitMinor > maxAmountMinor {
		writeError(w, r, badRequest("limit must be a positive amount"))
		return
	}
	budget, err := s.store.SaveBudget(r.Context(), categoryID, body.LimitMinor)
	if errors.Is(err, ErrInvalid) {
		writeError(w, r, badRequest("budgets go on expense categories"))
		return
	}
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, budget)
}

func (s *Server) removeBudget(w http.ResponseWriter, r *http.Request) {
	categoryID, err := uuid.Parse(chi.URLParam(r, "categoryId"))
	if err != nil {
		writeError(w, r, errNotFound)
		return
	}
	if err := s.store.RemoveBudget(r.Context(), categoryID); err != nil {
		writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type holdingBody struct {
	OwnerID        *uuid.UUID `json:"ownerId"`
	Name           string     `json:"name"`
	Badge          string     `json:"badge"`
	AssetType      string     `json:"assetType"`
	Units          string     `json:"units"`
	AvgCostMinor   int64      `json:"avgCostMinor"`
	LastPriceMinor int64      `json:"lastPriceMinor"`
	SipMinor       int64      `json:"sipMinor"`
	Color          string     `json:"color"`
	Note           string     `json:"note"`
}

func (b holdingBody) validate() (Holding, error) {
	name, note, badge := strings.TrimSpace(b.Name), strings.TrimSpace(b.Note), strings.TrimSpace(b.Badge)
	inRange := func(minor int64) bool { return minor >= 0 && minor <= maxAmountMinor }
	switch {
	case !textBetween(name, 1, 80):
		return Holding{}, badRequest("name must be 1 to 80 characters")
	case !textBetween(badge, 1, 8):
		return Holding{}, badRequest("badge must be 1 to 8 characters")
	case !assetTypes[b.AssetType]:
		return Holding{}, badRequest("unknown asset type")
	case !unitCount.MatchString(b.Units):
		return Holding{}, badRequest("units must be a plain number with up to 6 decimals")
	case !inRange(b.AvgCostMinor) || !inRange(b.LastPriceMinor) || !inRange(b.SipMinor):
		return Holding{}, badRequest("amounts must be zero or positive")
	case !hexColor.MatchString(b.Color):
		return Holding{}, badRequest("color must be #RRGGBB")
	case !textBetween(note, 0, 120):
		return Holding{}, badRequest("detail must be at most 120 characters")
	}
	return Holding{OwnerID: b.OwnerID, Name: name, Badge: badge, AssetType: b.AssetType, Units: b.Units, AvgCostMinor: b.AvgCostMinor, LastPriceMinor: b.LastPriceMinor, SipMinor: b.SipMinor, Color: b.Color, Note: note}, nil
}

func (s *Server) createHolding(w http.ResponseWriter, r *http.Request) {
	s.writeHolding(w, r, nil, http.StatusCreated)
}

func (s *Server) replaceHolding(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, r, errNotFound)
		return
	}
	s.writeHolding(w, r, &id, http.StatusOK)
}

func (s *Server) writeHolding(w http.ResponseWriter, r *http.Request, id *uuid.UUID, status int) {
	var body holdingBody
	if err := decode(r, &body); err != nil {
		writeError(w, r, err)
		return
	}
	holding, err := body.validate()
	if err != nil {
		writeError(w, r, err)
		return
	}
	saved, err := s.store.SaveHolding(r.Context(), id, holding)
	if errors.Is(err, ErrInvalid) {
		writeError(w, r, badRequest("that owner is not a member here"))
		return
	}
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, status, saved)
}

func (s *Server) removeHolding(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, r, errNotFound)
		return
	}
	if err := s.store.RemoveHolding(r.Context(), id); err != nil {
		writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func decode(r *http.Request, into any) error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(into); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return apiError{status: http.StatusRequestEntityTooLarge, Code: "too_large", Message: "request body too large"}
		}
		return badRequest("request body is not valid JSON for this endpoint")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("write response: %v", err)
	}
}

// writeError sends the client a sanitised error and logs unexpected ones with the request id only.
func writeError(w http.ResponseWriter, r *http.Request, err error) {
	var api apiError
	switch {
	case errors.As(err, &api):
	case errors.Is(err, ErrNotFound):
		api = errNotFound
	default:
		log.Printf("request %s %s %s failed: %v", middleware.GetReqID(r.Context()), r.Method, r.URL.Path, err)
		api = errInternal
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(api.status)
	_ = json.NewEncoder(w).Encode(map[string]apiError{"error": api})
}

func validDate(value string) bool {
	if !isoDate.MatchString(value) {
		return false
	}
	_, err := time.Parse("2006-01-02", value)
	return err == nil
}

func textBetween(value string, min, max int) bool {
	length := utf8.RuneCountInString(value)
	return utf8.ValidString(value) && length >= min && length <= max
}

func oneOfOrNil(value *string, allowed map[string]bool) bool {
	return value == nil || allowed[*value]
}

func set(values ...string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, value := range values {
		out[value] = true
	}
	return out
}

// loginLimiter counts failed sign-ins per username over a sliding window. It keys on the
// username alone because a client-supplied address is spoofable, and it is in memory
// because Home runs as one process and a restart forgetting the count is acceptable.
type loginLimiter struct {
	mu       sync.Mutex
	failures map[string][]time.Time
}

func (l *loginLimiter) recent(key string, now time.Time) []time.Time {
	kept := l.failures[key][:0]
	for _, at := range l.failures[key] {
		if now.Sub(at) < loginWindow {
			kept = append(kept, at)
		}
	}
	if len(kept) == 0 {
		delete(l.failures, key)
		return nil
	}
	l.failures[key] = kept
	return kept
}

func (l *loginLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.recent(key, time.Now())) < loginFailures
}

func (l *loginLimiter) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if len(l.failures) >= maxTrackedLogins {
		for tracked := range l.failures {
			l.recent(tracked, now)
		}
	}
	l.failures[key] = append(l.recent(key, now), now)
}

func (l *loginLimiter) clear(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, key)
}
