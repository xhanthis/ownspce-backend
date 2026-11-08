// Package home is the backend of Home, a household ledger for one family.
//
// It is deliberately plain: one server holds one home, every account on it is a
// member of the same ledger, and rows are stored readable. Accounts are made
// from the command line (cmd/home adduser), so there is no sign-up endpoint to
// defend. All SQL for it lives in this file.
package home

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed schema.sql
var schemaSQL string

//go:embed inventory_schema.sql
var inventorySchemaSQL string

//go:embed fixed_schema.sql
var fixedSchemaSQL string

var (
	ErrNotFound = errors.New("home: not found")
	ErrConflict = errors.New("home: conflict")
	ErrInvalid  = errors.New("home: invalid reference")
)

// MaxEntriesPerRead caps one ledger read so a wide period cannot pull an unbounded result.
const MaxEntriesPerRead = 5000

// MaxImportRows caps one CSV import so it lands well inside the request timeout.
const MaxImportRows = 2000

const maxMembers = 100

type Store struct {
	pool *pgxpool.Pool

	// Applied is true when this Open ran the schema and seeds, false when the database already matched.
	Applied bool
}

// schemaFingerprint names this build's schema and seed data. The database remembers the last one applied, so a
// cold start whose fingerprint matches skips every schema statement and both seeds: one read instead of eight.
func schemaFingerprint() string {
	sum := sha256.Sum256([]byte(schemaSQL + inventorySchemaSQL + fixedSchemaSQL + string(dishLibraryJSON)))
	return hex.EncodeToString(sum[:8])
}

type User struct {
	ID           uuid.UUID `json:"id"`
	Username     string    `json:"username"`
	Name         string    `json:"name"`
	Theme        string    `json:"theme"`
	Palette      string    `json:"palette"`
	Font         string    `json:"font"`
	passwordHash string
}

type Member struct {
	ID       uuid.UUID `json:"id"`
	Username string    `json:"username"`
	Name     string    `json:"name"`
}

type Settings struct {
	Name               string `json:"name"`
	Currency           string `json:"currency"`
	SharedByDefault    bool   `json:"sharedByDefault"`
	IncomeTracking     bool   `json:"incomeTracking"`
	OverallBudgetMinor *int64 `json:"overallBudgetMinor"`
}

type Category struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Emoji     string    `json:"emoji"`
	Color     string    `json:"color"`
	Kind      string    `json:"kind"`
	SortOrder int       `json:"sortOrder"`
	Archived  bool      `json:"archived"`
}

type Entry struct {
	ID          uuid.UUID  `json:"id"`
	OccurredOn  string     `json:"occurredOn"`
	Type        string     `json:"type"`
	AmountMinor int64      `json:"amountMinor"`
	CategoryID  uuid.UUID  `json:"categoryId"`
	Note        string     `json:"note"`
	IsShared    bool       `json:"isShared"`
	PaidBy      *uuid.UUID `json:"paidBy"`
	CreatedBy   *uuid.UUID `json:"createdBy"`
	UpdatedAt   time.Time  `json:"updatedAt"`
}

type Budget struct {
	CategoryID uuid.UUID `json:"categoryId"`
	LimitMinor int64     `json:"limitMinor"`
}

type Holding struct {
	ID             uuid.UUID  `json:"id"`
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
	PricedAt       time.Time  `json:"pricedAt"`
}

// SettingsPatch carries only the settings a request named; a nil field is left alone.
type SettingsPatch struct {
	Name               *string
	SharedByDefault    *bool
	IncomeTracking     *bool
	SetOverallBudget   bool
	OverallBudgetMinor *int64
}

// ProfilePatch carries only the profile fields a request named.
type ProfilePatch struct {
	Name    *string
	Theme   *string
	Palette *string
	Font    *string
}

var seedCategories = []Category{
	{Name: "Groceries", Emoji: "🛒", Color: "#5FAF9F", Kind: "expense"},
	{Name: "Food", Emoji: "🍔", Color: "#EC7A58", Kind: "expense"},
	{Name: "Transport", Emoji: "🚆", Color: "#279AF4", Kind: "expense"},
	{Name: "Rent", Emoji: "🏠", Color: "#6E7BF1", Kind: "expense"},
	{Name: "Utilities", Emoji: "💡", Color: "#F3BF56", Kind: "expense"},
	{Name: "Subscriptions", Emoji: "🔄", Color: "#C56AF7", Kind: "expense"},
	{Name: "Healthcare", Emoji: "🚑", Color: "#E34D63", Kind: "expense"},
	{Name: "Education", Emoji: "📚", Color: "#4088AD", Kind: "expense"},
	{Name: "Shopping", Emoji: "👔", Color: "#ED80A2", Kind: "expense"},
	{Name: "Kids", Emoji: "🧸", Color: "#7CB0AA", Kind: "expense"},
	{Name: "Travel", Emoji: "✈️", Color: "#84B4EB", Kind: "expense"},
	{Name: "Household", Emoji: "🧹", Color: "#C38D5D", Kind: "expense"},
	{Name: "Salary", Emoji: "💰", Color: "#03CD86", Kind: "income"},
	{Name: "Freelance", Emoji: "💼", Color: "#88997A", Kind: "income"},
	{Name: "Dividends", Emoji: "💹", Color: "#5FAF9F", Kind: "income"},
	{Name: "Rent income", Emoji: "🏘", Color: "#A6678A", Kind: "income"},
	{Name: "Gifts", Emoji: "🧧", Color: "#D46D7F", Kind: "income"},
}

// Open connects to Postgres and brings the schema and seeds up to this build, skipping all of it when the
// database already carries this build's fingerprint.
// Args: ctx, databaseURL (a Postgres connection string)
// Returns: a ready Store, or an error when the database is unreachable or the schema fails
// Handles: concurrent first boots — the schema and seeds run under a transaction-scoped advisory lock
func Open(ctx context.Context, databaseURL string) (*Store, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}
	config.MaxConns = 4
	config.MinConns = 0
	config.ConnConfig.ConnectTimeout = 5 * time.Second
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeExec
	config.ConnConfig.StatementCacheCapacity = 0
	config.ConnConfig.DescriptionCacheCapacity = 0

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	store := &Store{pool: pool}
	if err := store.migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() { s.pool.Close() }

// storedFingerprint reads the fingerprint the database last recorded; empty when none is recorded yet or the
// meta table does not exist (a database older than this mechanism).
func (s *Store) storedFingerprint(ctx context.Context, db interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}) (string, error) {
	var stored string
	err := db.QueryRow(ctx, "SELECT value FROM home_meta WHERE key = 'schema'").Scan(&stored)
	if errors.Is(err, pgx.ErrNoRows) || isCode(err, "42P01") {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read schema fingerprint: %w", err)
	}
	return stored, nil
}

// migrate applies the schema files and seeds unless the database already records this build's fingerprint.
// Handles: a database without the fingerprint table yet (first boot of this build) → full run; two instances
// booting together → the lock serialises them, and the second re-reads the fingerprint under it and does nothing
func (s *Store) migrate(ctx context.Context) error {
	fingerprint := schemaFingerprint()
	stored, err := s.storedFingerprint(ctx, s.pool)
	if err != nil {
		return err
	}
	if stored == fingerprint {
		return nil
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(7340101)"); err != nil {
			return fmt.Errorf("lock schema: %w", err)
		}
		if _, err := tx.Exec(ctx, "CREATE TABLE IF NOT EXISTS home_meta (key text PRIMARY KEY, value text NOT NULL, updated_at timestamptz NOT NULL DEFAULT now())"); err != nil {
			return fmt.Errorf("meta table: %w", err)
		}
		if stored, err := s.storedFingerprint(ctx, tx); err != nil {
			return err
		} else if stored == fingerprint {
			return nil
		}
		s.Applied = true
		if _, err := tx.Exec(ctx, schemaSQL); err != nil {
			return fmt.Errorf("apply schema: %w", err)
		}
		if _, err := tx.Exec(ctx, inventorySchemaSQL); err != nil {
			return fmt.Errorf("apply inventory schema: %w", err)
		}
		if _, err := tx.Exec(ctx, fixedSchemaSQL); err != nil {
			return fmt.Errorf("apply fixed schema: %w", err)
		}
		var seeded bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM home_categories)").Scan(&seeded); err != nil {
			return fmt.Errorf("check categories: %w", err)
		}
		if !seeded {
			batch := &pgx.Batch{}
			for index, category := range seedCategories {
				batch.Queue("INSERT INTO home_categories (id, name, emoji, color, kind, sort_order) VALUES ($1, $2, $3, $4, $5, $6)", uuid.New(), category.Name, category.Emoji, category.Color, category.Kind, index)
			}
			if err := tx.SendBatch(ctx, batch).Close(); err != nil {
				return fmt.Errorf("seed categories: %w", err)
			}
		}
		if _, err := seedDishes(ctx, tx); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "INSERT INTO home_meta (key, value, updated_at) VALUES ('schema', $1, now()) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()", fingerprint); err != nil {
			return fmt.Errorf("record schema fingerprint: %w", err)
		}
		return nil
	})
}

// CreateUser adds an account to the home.
// Args: ctx, username (already normalised), name, passwordHash (bcrypt)
// Returns: the new user, or ErrConflict when the username is taken
func (s *Store) CreateUser(ctx context.Context, username, name, passwordHash string) (User, error) {
	user := User{ID: uuid.New(), Username: username, Name: name, Theme: "system", Palette: "cream", Font: "grotesk"}
	_, err := s.pool.Exec(ctx, "INSERT INTO home_users (id, username, name, password_hash) VALUES ($1, $2, $3, $4)", user.ID, username, name, passwordHash)
	if isCode(err, "23505") {
		return User{}, ErrConflict
	}
	if err != nil {
		return User{}, fmt.Errorf("create user: %w", err)
	}
	return user, nil
}

// SetPassword replaces an account's password and signs every session on it out.
// Args: ctx, username, passwordHash (bcrypt)
// Returns: ErrNotFound when no such account exists
func (s *Store) SetPassword(ctx context.Context, username, passwordHash string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var id uuid.UUID
		err := tx.QueryRow(ctx, "UPDATE home_users SET password_hash = $2 WHERE username = $1 RETURNING id", username, passwordHash).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("set password: %w", err)
		}
		if _, err := tx.Exec(ctx, "DELETE FROM home_sessions WHERE user_id = $1", id); err != nil {
			return fmt.Errorf("end sessions: %w", err)
		}
		return nil
	})
}

// UserByUsername reads an account with its password hash, for signing in.
// Returns: ErrNotFound when no such account exists
func (s *Store) UserByUsername(ctx context.Context, username string) (User, error) {
	var user User
	err := s.pool.QueryRow(ctx, "SELECT id, username, name, theme, palette, font, password_hash FROM home_users WHERE username = $1", username).Scan(&user.ID, &user.Username, &user.Name, &user.Theme, &user.Palette, &user.Font, &user.passwordHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("read user: %w", err)
	}
	return user, nil
}

// CreateSession files a session for a signed-in account.
// Args: ctx, tokenHash (sha256 hex of the bearer token — the token itself is never stored), userID, ttl
func (s *Store) CreateSession(ctx context.Context, tokenHash string, userID uuid.UUID, ttl time.Duration) error {
	_, err := s.pool.Exec(ctx, "INSERT INTO home_sessions (token_hash, user_id, expires_at) VALUES ($1, $2, $3)", tokenHash, userID, time.Now().Add(ttl))
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

// UserBySession resolves a live session to its account.
// Returns: ErrNotFound when the session is unknown or expired
func (s *Store) UserBySession(ctx context.Context, tokenHash string) (User, error) {
	var user User
	err := s.pool.QueryRow(ctx, "SELECT u.id, u.username, u.name, u.theme, u.palette, u.font FROM home_sessions s JOIN home_users u ON u.id = s.user_id WHERE s.token_hash = $1 AND s.expires_at > now()", tokenHash).Scan(&user.ID, &user.Username, &user.Name, &user.Theme, &user.Palette, &user.Font)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("read session: %w", err)
	}
	return user, nil
}

// EndSession signs one session out. Unknown tokens are not an error.
func (s *Store) EndSession(ctx context.Context, tokenHash string) error {
	if _, err := s.pool.Exec(ctx, "DELETE FROM home_sessions WHERE token_hash = $1", tokenHash); err != nil {
		return fmt.Errorf("end session: %w", err)
	}
	return nil
}

// UpdateProfile changes the named fields of one account.
// Returns: the account as it now stands
func (s *Store) UpdateProfile(ctx context.Context, userID uuid.UUID, patch ProfilePatch) (User, error) {
	var user User
	err := s.pool.QueryRow(ctx, "UPDATE home_users SET name = COALESCE($2::text, name), theme = COALESCE($3::text, theme), palette = COALESCE($4::text, palette), font = COALESCE($5::text, font) WHERE id = $1 RETURNING id, username, name, theme, palette, font", userID, patch.Name, patch.Theme, patch.Palette, patch.Font).Scan(&user.ID, &user.Username, &user.Name, &user.Theme, &user.Palette, &user.Font)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("update profile: %w", err)
	}
	return user, nil
}

// Members lists every account in the home, oldest first.
func (s *Store) Members(ctx context.Context) ([]Member, error) {
	rows, err := s.pool.Query(ctx, "SELECT id, username, name FROM home_users ORDER BY created_at, id LIMIT $1", maxMembers)
	if err != nil {
		return nil, fmt.Errorf("list members: %w", err)
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Member, error) {
		var member Member
		err := row.Scan(&member.ID, &member.Username, &member.Name)
		return member, err
	})
}

func (s *Store) Settings(ctx context.Context) (Settings, error) {
	var settings Settings
	err := s.pool.QueryRow(ctx, "SELECT name, currency, shared_by_default, income_tracking, overall_budget_minor FROM home_settings WHERE id = 1").Scan(&settings.Name, &settings.Currency, &settings.SharedByDefault, &settings.IncomeTracking, &settings.OverallBudgetMinor)
	if err != nil {
		return Settings{}, fmt.Errorf("read settings: %w", err)
	}
	return settings, nil
}

// UpdateSettings changes the named household settings.
// Returns: the settings as they now stand
func (s *Store) UpdateSettings(ctx context.Context, patch SettingsPatch) (Settings, error) {
	var settings Settings
	err := s.pool.QueryRow(ctx, "UPDATE home_settings SET name = COALESCE($1::text, name), shared_by_default = COALESCE($2::boolean, shared_by_default), income_tracking = COALESCE($3::boolean, income_tracking), overall_budget_minor = CASE WHEN $4::boolean THEN $5::bigint ELSE overall_budget_minor END, updated_at = now() WHERE id = 1 RETURNING name, currency, shared_by_default, income_tracking, overall_budget_minor", patch.Name, patch.SharedByDefault, patch.IncomeTracking, patch.SetOverallBudget, patch.OverallBudgetMinor).Scan(&settings.Name, &settings.Currency, &settings.SharedByDefault, &settings.IncomeTracking, &settings.OverallBudgetMinor)
	if err != nil {
		return Settings{}, fmt.Errorf("update settings: %w", err)
	}
	return settings, nil
}

func (s *Store) Categories(ctx context.Context) ([]Category, error) {
	rows, err := s.pool.Query(ctx, "SELECT id, name, emoji, color, kind, sort_order, archived FROM home_categories ORDER BY sort_order, id LIMIT 500")
	if err != nil {
		return nil, fmt.Errorf("list categories: %w", err)
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Category, error) {
		var category Category
		err := row.Scan(&category.ID, &category.Name, &category.Emoji, &category.Color, &category.Kind, &category.SortOrder, &category.Archived)
		return category, err
	})
}

func (s *Store) categoryKind(ctx context.Context, id uuid.UUID) (string, error) {
	var kind string
	err := s.pool.QueryRow(ctx, "SELECT kind FROM home_categories WHERE id = $1", id).Scan(&kind)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrInvalid
	}
	if err != nil {
		return "", fmt.Errorf("read category: %w", err)
	}
	return kind, nil
}

// Entries reads the ledger between two dates inclusive, newest first.
// Args: ctx, from, to (yyyy-mm-dd, validated by the caller)
// Returns: up to MaxEntriesPerRead rows, and whether more existed beyond the cap
func (s *Store) Entries(ctx context.Context, from, to string) ([]Entry, bool, error) {
	rows, err := s.pool.Query(ctx, "SELECT id, to_char(occurred_on, 'YYYY-MM-DD'), type, amount_minor, category_id, note, is_shared, paid_by, created_by, updated_at FROM home_entries WHERE occurred_on BETWEEN $1::date AND $2::date ORDER BY occurred_on DESC, id DESC LIMIT $3", from, to, MaxEntriesPerRead+1)
	if err != nil {
		return nil, false, fmt.Errorf("list entries: %w", err)
	}
	entries, err := pgx.CollectRows(rows, scanEntry)
	if err != nil {
		return nil, false, fmt.Errorf("scan entries: %w", err)
	}
	if len(entries) > MaxEntriesPerRead {
		return entries[:MaxEntriesPerRead], true, nil
	}
	return entries, false, nil
}

func scanEntry(row pgx.CollectableRow) (Entry, error) {
	var entry Entry
	err := row.Scan(&entry.ID, &entry.OccurredOn, &entry.Type, &entry.AmountMinor, &entry.CategoryID, &entry.Note, &entry.IsShared, &entry.PaidBy, &entry.CreatedBy, &entry.UpdatedAt)
	return entry, err
}

// SaveEntry creates an entry (id nil) or replaces the editable fields of an existing one.
// Args: ctx, id (nil to create), entry (validated by the caller), actor (who is writing)
// Returns: the stored entry; ErrInvalid when the category is unknown or of the other kind,
// or the payer is not a member; ErrNotFound when updating an entry that does not exist
func (s *Store) SaveEntry(ctx context.Context, id *uuid.UUID, entry Entry, actor uuid.UUID) (Entry, error) {
	kind, err := s.categoryKind(ctx, entry.CategoryID)
	if err != nil {
		return Entry{}, err
	}
	if kind != entry.Type {
		return Entry{}, ErrInvalid
	}

	var row pgx.Row
	if id == nil {
		row = s.pool.QueryRow(ctx, "INSERT INTO home_entries (id, occurred_on, type, amount_minor, category_id, note, is_shared, paid_by, created_by) VALUES ($1, $2::date, $3, $4, $5, $6, $7, $8, $9) RETURNING id, to_char(occurred_on, 'YYYY-MM-DD'), type, amount_minor, category_id, note, is_shared, paid_by, created_by, updated_at", uuid.New(), entry.OccurredOn, entry.Type, entry.AmountMinor, entry.CategoryID, entry.Note, entry.IsShared, entry.PaidBy, actor)
	} else {
		row = s.pool.QueryRow(ctx, "UPDATE home_entries SET occurred_on = $2::date, type = $3, amount_minor = $4, category_id = $5, note = $6, is_shared = $7, paid_by = $8, updated_at = now() WHERE id = $1 RETURNING id, to_char(occurred_on, 'YYYY-MM-DD'), type, amount_minor, category_id, note, is_shared, paid_by, created_by, updated_at", *id, entry.OccurredOn, entry.Type, entry.AmountMinor, entry.CategoryID, entry.Note, entry.IsShared, entry.PaidBy)
	}

	var saved Entry
	err = row.Scan(&saved.ID, &saved.OccurredOn, &saved.Type, &saved.AmountMinor, &saved.CategoryID, &saved.Note, &saved.IsShared, &saved.PaidBy, &saved.CreatedBy, &saved.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Entry{}, ErrNotFound
	}
	if isCode(err, "23503") {
		return Entry{}, ErrInvalid
	}
	if err != nil {
		return Entry{}, fmt.Errorf("save entry: %w", err)
	}
	return saved, nil
}

// ImportResult counts what an import added and what it left out because the ledger already had it.
type ImportResult struct {
	Created    int `json:"created"`
	Duplicates int `json:"duplicates"`
}

type entryKey struct {
	day, kind, category, note string
	amount                    int64
}

// ImportEntries adds many entries in one transaction, leaving out rows the ledger already holds.
// A row counts as held when an entry has the same day, type, category, amount and note; matching
// is one for one, so a file with two identical rows against one stored entry adds one.
// Args: ctx, entries (validated by the caller, at most MaxImportRows), actor (who is importing),
// dryRun (count only and write nothing)
// Returns: the counts; ErrInvalid when a category is unknown or of the other kind, or a payer is not a member
// Handles: two imports at once (serialised by a transaction lock), a failure part way (nothing is kept)
func (s *Store) ImportEntries(ctx context.Context, entries []Entry, actor uuid.UUID, dryRun bool) (ImportResult, error) {
	var result ImportResult
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(7340102)"); err != nil {
			return fmt.Errorf("lock import: %w", err)
		}

		categoryIDs := make([]string, 0, len(entries))
		seen := map[uuid.UUID]bool{}
		days, kinds, categories, notes := make([]string, len(entries)), make([]string, len(entries)), make([]string, len(entries)), make([]string, len(entries))
		amounts := make([]int64, len(entries))
		for index, entry := range entries {
			if !seen[entry.CategoryID] {
				seen[entry.CategoryID] = true
				categoryIDs = append(categoryIDs, entry.CategoryID.String())
			}
			days[index], kinds[index], categories[index], notes[index], amounts[index] = entry.OccurredOn, entry.Type, entry.CategoryID.String(), entry.Note, entry.AmountMinor
		}

		rows, err := tx.Query(ctx, "SELECT id::text, kind FROM home_categories WHERE id = ANY($1::uuid[]) LIMIT $2", categoryIDs, len(categoryIDs))
		if err != nil {
			return fmt.Errorf("read import categories: %w", err)
		}
		categoryKinds := map[string]string{}
		var id, kind string
		if _, err := pgx.ForEachRow(rows, []any{&id, &kind}, func() error {
			categoryKinds[id] = kind
			return nil
		}); err != nil {
			return fmt.Errorf("scan import categories: %w", err)
		}
		for _, entry := range entries {
			if categoryKinds[entry.CategoryID.String()] != entry.Type {
				return ErrInvalid
			}
		}

		rows, err = tx.Query(ctx, "SELECT to_char(e.occurred_on, 'YYYY-MM-DD'), e.type, e.category_id::text, e.amount_minor, e.note, count(*) FROM home_entries e JOIN (SELECT DISTINCT day, kind, category_id, amount_minor, note FROM unnest($1::date[], $2::text[], $3::uuid[], $4::bigint[], $5::text[]) AS k(day, kind, category_id, amount_minor, note)) k ON e.occurred_on = k.day AND e.type = k.kind AND e.category_id = k.category_id AND e.amount_minor = k.amount_minor AND e.note = k.note GROUP BY e.occurred_on, e.type, e.category_id, e.amount_minor, e.note LIMIT $6", days, kinds, categories, amounts, notes, len(entries))
		if err != nil {
			return fmt.Errorf("match existing entries: %w", err)
		}
		held := map[entryKey]int{}
		var key entryKey
		var count int
		if _, err := pgx.ForEachRow(rows, []any{&key.day, &key.kind, &key.category, &key.amount, &key.note, &count}, func() error {
			held[key] = count
			return nil
		}); err != nil {
			return fmt.Errorf("scan existing entries: %w", err)
		}

		var ids, newDays, newKinds, newCategories, newNotes, payers []string
		var shared []bool
		var newAmounts []int64
		for index, entry := range entries {
			key := entryKey{day: days[index], kind: kinds[index], category: categories[index], note: notes[index], amount: amounts[index]}
			if held[key] > 0 {
				held[key]--
				result.Duplicates++
				continue
			}
			payer := ""
			if entry.PaidBy != nil {
				payer = entry.PaidBy.String()
			}
			ids = append(ids, uuid.NewString())
			newDays, newKinds, newCategories, newNotes = append(newDays, key.day), append(newKinds, key.kind), append(newCategories, key.category), append(newNotes, key.note)
			newAmounts, shared, payers = append(newAmounts, key.amount), append(shared, entry.IsShared), append(payers, payer)
		}
		result.Created = len(ids)
		if dryRun || len(ids) == 0 {
			return nil
		}

		_, err = tx.Exec(ctx, "INSERT INTO home_entries (id, occurred_on, type, amount_minor, category_id, note, is_shared, paid_by, created_by) SELECT id, day, kind, amount_minor, category_id, note, is_shared, NULLIF(payer, '')::uuid, $9 FROM unnest($1::uuid[], $2::date[], $3::text[], $4::bigint[], $5::uuid[], $6::text[], $7::boolean[], $8::text[]) AS r(id, day, kind, amount_minor, category_id, note, is_shared, payer)", ids, newDays, newKinds, newAmounts, newCategories, newNotes, shared, payers, actor)
		if isCode(err, "23503") {
			return ErrInvalid
		}
		if err != nil {
			return fmt.Errorf("insert imported entries: %w", err)
		}
		return nil
	})
	if err != nil {
		return ImportResult{}, err
	}
	return result, nil
}

// RemoveEntry takes one entry out of the ledger.
// Returns: ErrNotFound when there is no such entry
func (s *Store) RemoveEntry(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, "DELETE FROM home_entries WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("remove entry: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) Budgets(ctx context.Context) ([]Budget, error) {
	rows, err := s.pool.Query(ctx, "SELECT category_id, limit_minor FROM home_budgets ORDER BY category_id LIMIT 500")
	if err != nil {
		return nil, fmt.Errorf("list budgets: %w", err)
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Budget, error) {
		var budget Budget
		err := row.Scan(&budget.CategoryID, &budget.LimitMinor)
		return budget, err
	})
}

// SaveBudget sets the monthly ceiling on one expense category.
// Returns: ErrInvalid when the category is unknown or is an income category
func (s *Store) SaveBudget(ctx context.Context, categoryID uuid.UUID, limitMinor int64) (Budget, error) {
	kind, err := s.categoryKind(ctx, categoryID)
	if err != nil {
		return Budget{}, err
	}
	if kind != "expense" {
		return Budget{}, ErrInvalid
	}
	_, err = s.pool.Exec(ctx, "INSERT INTO home_budgets (category_id, limit_minor) VALUES ($1, $2) ON CONFLICT (category_id) DO UPDATE SET limit_minor = EXCLUDED.limit_minor, updated_at = now()", categoryID, limitMinor)
	if err != nil {
		return Budget{}, fmt.Errorf("save budget: %w", err)
	}
	return Budget{CategoryID: categoryID, LimitMinor: limitMinor}, nil
}

// RemoveBudget lifts the ceiling on one category; the entries under it are untouched.
// Returns: ErrNotFound when that category had no ceiling
func (s *Store) RemoveBudget(ctx context.Context, categoryID uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, "DELETE FROM home_budgets WHERE category_id = $1", categoryID)
	if err != nil {
		return fmt.Errorf("remove budget: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) Holdings(ctx context.Context) ([]Holding, error) {
	rows, err := s.pool.Query(ctx, "SELECT id, owner_id, name, badge, asset_type, units::text, avg_cost_minor, last_price_minor, sip_minor, color, note, priced_at FROM home_holdings ORDER BY created_at, id LIMIT 1000")
	if err != nil {
		return nil, fmt.Errorf("list holdings: %w", err)
	}
	return pgx.CollectRows(rows, scanHolding)
}

func scanHolding(row pgx.CollectableRow) (Holding, error) {
	var holding Holding
	err := row.Scan(&holding.ID, &holding.OwnerID, &holding.Name, &holding.Badge, &holding.AssetType, &holding.Units, &holding.AvgCostMinor, &holding.LastPriceMinor, &holding.SipMinor, &holding.Color, &holding.Note, &holding.PricedAt)
	return holding, err
}

// SaveHolding creates a holding (id nil) or replaces an existing one, stamping it as priced now.
// Returns: the stored holding; ErrInvalid when the owner is not a member; ErrNotFound on a missing id
func (s *Store) SaveHolding(ctx context.Context, id *uuid.UUID, holding Holding) (Holding, error) {
	var row pgx.Row
	if id == nil {
		row = s.pool.QueryRow(ctx, "INSERT INTO home_holdings (id, owner_id, name, badge, asset_type, units, avg_cost_minor, last_price_minor, sip_minor, color, note) VALUES ($1, $2, $3, $4, $5, $6::numeric, $7, $8, $9, $10, $11) RETURNING id, owner_id, name, badge, asset_type, units::text, avg_cost_minor, last_price_minor, sip_minor, color, note, priced_at", uuid.New(), holding.OwnerID, holding.Name, holding.Badge, holding.AssetType, holding.Units, holding.AvgCostMinor, holding.LastPriceMinor, holding.SipMinor, holding.Color, holding.Note)
	} else {
		row = s.pool.QueryRow(ctx, "UPDATE home_holdings SET owner_id = $2, name = $3, badge = $4, asset_type = $5, units = $6::numeric, avg_cost_minor = $7, last_price_minor = $8, sip_minor = $9, color = $10, note = $11, priced_at = now() WHERE id = $1 RETURNING id, owner_id, name, badge, asset_type, units::text, avg_cost_minor, last_price_minor, sip_minor, color, note, priced_at", *id, holding.OwnerID, holding.Name, holding.Badge, holding.AssetType, holding.Units, holding.AvgCostMinor, holding.LastPriceMinor, holding.SipMinor, holding.Color, holding.Note)
	}

	var saved Holding
	err := row.Scan(&saved.ID, &saved.OwnerID, &saved.Name, &saved.Badge, &saved.AssetType, &saved.Units, &saved.AvgCostMinor, &saved.LastPriceMinor, &saved.SipMinor, &saved.Color, &saved.Note, &saved.PricedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Holding{}, ErrNotFound
	}
	if isCode(err, "23503") {
		return Holding{}, ErrInvalid
	}
	if err != nil {
		return Holding{}, fmt.Errorf("save holding: %w", err)
	}
	return saved, nil
}

// RemoveHolding takes one holding out of the portfolio.
// Returns: ErrNotFound when there is no such holding
func (s *Store) RemoveHolding(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, "DELETE FROM home_holdings WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("remove holding: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// LoginFailures counts the failed sign-ins on one username in the window starting at windowStart.
func (s *Store) LoginFailures(ctx context.Context, username string, windowStart time.Time) (int, error) {
	var failures int
	err := s.pool.QueryRow(ctx, "SELECT failures FROM home_login_failures WHERE username = $1 AND window_start = $2", username, windowStart).Scan(&failures)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read login failures: %w", err)
	}
	return failures, nil
}

// RecordLoginFailure adds one failed sign-in to the username's current window, atomically.
func (s *Store) RecordLoginFailure(ctx context.Context, username string, windowStart time.Time) error {
	_, err := s.pool.Exec(ctx, "INSERT INTO home_login_failures (username, window_start, failures) VALUES ($1, $2, 1) ON CONFLICT (username, window_start) DO UPDATE SET failures = home_login_failures.failures + 1", username, windowStart)
	if err != nil {
		return fmt.Errorf("record login failure: %w", err)
	}
	return nil
}

// ClearLoginFailures forgets a username's failures after it signs in, and sweeps windows older than a day.
func (s *Store) ClearLoginFailures(ctx context.Context, username string) error {
	if _, err := s.pool.Exec(ctx, "DELETE FROM home_login_failures WHERE username = $1 OR window_start < now() - interval '1 day'", username); err != nil {
		return fmt.Errorf("clear login failures: %w", err)
	}
	return nil
}

func isCode(err error, code string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == code
}
