package store

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Money is the one part of this database that stores readable user content.
//
// Every other table treats the server as a content-blind relay: note bodies,
// task titles and page trees arrive sealed and leave sealed. The money tables
// deliberately break that rule, because the product they serve is arithmetic —
// budgets, category splits, settlement between household members and portfolio
// valuation all have to be computed over the values themselves, and a server
// that cannot read an amount cannot add two of them up.
//
// The consequence is stated plainly rather than hidden: an operator with
// database access can read a household's ledger. Access is still scoped by
// space membership on every statement below, and no money row is reachable
// without a role on its space.

// MaxTransactionAmountMinor caps a single entry at one billion rupees in paise,
// mirroring the digit limit the entry keypad enforces on the client. Amounts are
// stored in minor units as integers throughout: floating point is never correct
// for money, and paise is the smallest unit any supported currency needs.
const MaxTransactionAmountMinor int64 = 100000000000

// MoneySettings is the per-household configuration. Its existence is also the
// flag that money is enabled for a space: a space with no row here is a plain
// notes workspace and never appears in the money household list.
type MoneySettings struct {
	SpaceID                uuid.UUID
	Currency               string
	Locale                 string
	SharedByDefault        bool
	ApprovalThresholdMinor int64
	MonthlyCloseDay        int
	UpdatedAt              time.Time
}

// MoneyHousehold is a space with money enabled, as seen by one member.
type MoneyHousehold struct {
	SpaceID     uuid.UUID
	Role        string
	MemberCount int
	Settings    MoneySettings
}

// MoneyCategory is a spending or earning bucket. Colour and emoji live here
// rather than on the client so every member of a household sees one ledger.
type MoneyCategory struct {
	ID         uuid.UUID
	SpaceID    uuid.UUID
	Name       string
	Emoji      string
	Color      string
	Kind       string
	SortOrder  int
	ArchivedAt *time.Time
}

// MoneyAccount is where money sits: a bank account, a card, a wallet, cash.
type MoneyAccount struct {
	ID                  uuid.UUID
	SpaceID             uuid.UUID
	Name                string
	Kind                string
	Currency            string
	OpeningBalanceMinor int64
	IsShared            bool
	OwnerID             *uuid.UUID
	ArchivedAt          *time.Time
}

// MoneyTransaction is one entry in the ledger.
type MoneyTransaction struct {
	ID          uuid.UUID
	SpaceID     uuid.UUID
	ClientID    uuid.UUID
	AccountID   *uuid.UUID
	CategoryID  uuid.UUID
	Type        string
	AmountMinor int64
	Currency    string
	OccurredOn  time.Time
	Note        string
	IsShared    bool
	PaidBy      *uuid.UUID
	CreatedBy   *uuid.UUID
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// MoneyBudget is a monthly ceiling on one category.
type MoneyBudget struct {
	ID         uuid.UUID
	SpaceID    uuid.UUID
	CategoryID uuid.UUID
	Period     string
	LimitMinor int64
	StartsOn   time.Time
}

// MoneyBill is a recurring charge the household expects every month.
type MoneyBill struct {
	ID           uuid.UUID
	SpaceID      uuid.UUID
	Name         string
	Emoji        string
	CategoryID   *uuid.UUID
	AccountID    *uuid.UUID
	AmountMinor  int64
	DayOfMonth   int
	AutoLog      bool
	IsShared     bool
	PaidBy       *uuid.UUID
	LastLoggedOn *time.Time
	ArchivedAt   *time.Time
}

// MoneyHolding is one investment position. Units are exact decimals rather than
// integers because fractional mutual-fund units are normal, while both prices
// are integer minor units for the same reason transaction amounts are.
type MoneyHolding struct {
	ID             uuid.UUID
	SpaceID        uuid.UUID
	OwnerID        *uuid.UUID
	Name           string
	Badge          string
	AssetType      string
	Units          string
	AvgCostMinor   int64
	LastPriceMinor int64
	DayChangeBps   int
	SIPMinor       int64
	Currency       string
	Color          string
	PricedAt       *time.Time
	ArchivedAt     *time.Time
}

// MoneyInvite is an outstanding invitation to join a household by email.
//
// It exists alongside the encrypted product's own member flow rather than
// reusing it: that flow requires the inviter to wrap a space key for the
// invitee's devices, which presumes the invitee already has an account and a
// device key. A household inviting a parent who has never opened the app has
// neither, and money rows need no key to read.
type MoneyInvite struct {
	ID         uuid.UUID
	SpaceID    uuid.UUID
	Email      string
	Role       string
	InvitedBy  *uuid.UUID
	ExpiresAt  time.Time
	AcceptedAt *time.Time
	CreatedAt  time.Time
}

// seedCategories is the starting set every new household gets, so the first
// entry can be logged without setting anything up first.
var seedCategories = []MoneyCategory{
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

const moneySettingsColumns = `space_id, currency, locale, shared_by_default, approval_threshold_minor, monthly_close_day, updated_at`

func scanMoneySettings(row pgx.Row) (*MoneySettings, error) {
	var m MoneySettings
	if err := row.Scan(&m.SpaceID, &m.Currency, &m.Locale, &m.SharedByDefault, &m.ApprovalThresholdMinor, &m.MonthlyCloseDay, &m.UpdatedAt); err != nil {
		if noRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &m, nil
}

// EnableMoney turns a space into a money household, seeding the default
// category set in the same transaction.
// Args: ctx, spaceID
// Returns: the household settings, error
// Handles: already-enabled spaces, which return the existing settings unchanged
// rather than resetting them or duplicating the seed categories
func (s *Store) EnableMoney(ctx context.Context, spaceID uuid.UUID) (*MoneySettings, error) {
	var settings *MoneySettings
	err := s.tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, "INSERT INTO money_settings (space_id) VALUES ($1) ON CONFLICT (space_id) DO NOTHING", spaceID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() > 0 {
			for i, c := range seedCategories {
				if _, err := tx.Exec(ctx, "INSERT INTO money_categories (space_id, name, emoji, color, kind, sort_order) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (space_id, name) DO NOTHING", spaceID, c.Name, c.Emoji, c.Color, c.Kind, i); err != nil {
					return err
				}
			}
		}
		settings, err = scanMoneySettings(tx.QueryRow(ctx, "SELECT "+moneySettingsColumns+" FROM money_settings WHERE space_id = $1", spaceID))
		return err
	})
	if err != nil {
		return nil, err
	}
	return settings, nil
}

// CreateMoneyHousehold creates a space that exists only to hold a ledger.
//
// The encrypted product's own space creation demands a set of space keys wrapped
// to the caller's devices, and refuses to create a space nobody can decrypt.
// A money household has nothing to decrypt: its rows are readable by design. So
// it is created here without keys, which is also what lets a brand-new web
// session start a household without first performing a device-approval dance
// that protects data this space will never hold.
//
// A notes client listing this space sees wrappedKey: null — the state it already
// handles for a space whose key has not been granted yet.
// Args: ctx, ownerID
// Returns: the new space id, error
func (s *Store) CreateMoneyHousehold(ctx context.Context, ownerID uuid.UUID) (uuid.UUID, error) {
	var spaceID uuid.UUID
	err := s.tx(ctx, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, "INSERT INTO spaces (owner_id) VALUES ($1) RETURNING id", ownerID).Scan(&spaceID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "INSERT INTO space_members (space_id, user_id, role, invited_by) VALUES ($1, $2, 'owner', $2)", spaceID, ownerID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "INSERT INTO money_settings (space_id) VALUES ($1)", spaceID); err != nil {
			return err
		}
		for i, c := range seedCategories {
			if _, err := tx.Exec(ctx, "INSERT INTO money_categories (space_id, name, emoji, color, kind, sort_order) VALUES ($1, $2, $3, $4, $5, $6)", spaceID, c.Name, c.Emoji, c.Color, c.Kind, i); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return uuid.Nil, err
	}
	return spaceID, nil
}

// MoneySettingsFor reads one household's configuration.
// Args: ctx, spaceID
// Returns: settings, ErrNotFound when money is not enabled on the space
func (s *Store) MoneySettingsFor(ctx context.Context, spaceID uuid.UUID) (*MoneySettings, error) {
	return scanMoneySettings(s.pool.QueryRow(ctx, "SELECT "+moneySettingsColumns+" FROM money_settings WHERE space_id = $1", spaceID))
}

// UpdateMoneySettings applies a partial update to household configuration.
// Args: ctx, spaceID, currency/locale/sharedByDefault/approvalThresholdMinor/
// monthlyCloseDay (nil leaves the field untouched)
// Returns: the updated settings, ErrNotFound when money is not enabled
func (s *Store) UpdateMoneySettings(ctx context.Context, spaceID uuid.UUID, currency, locale *string, sharedByDefault *bool, approvalThresholdMinor *int64, monthlyCloseDay *int) (*MoneySettings, error) {
	return scanMoneySettings(s.pool.QueryRow(ctx, "UPDATE money_settings SET currency = COALESCE($2, currency), locale = COALESCE($3, locale), shared_by_default = COALESCE($4, shared_by_default), approval_threshold_minor = COALESCE($5, approval_threshold_minor), monthly_close_day = COALESCE($6, monthly_close_day), updated_at = now() WHERE space_id = $1 RETURNING "+moneySettingsColumns, spaceID, currency, locale, sharedByDefault, approvalThresholdMinor, monthlyCloseDay))
}

// ListMoneyHouseholds returns every money-enabled space the user belongs to,
// with the caller's role and the member count the household screen renders.
// Args: ctx, userID
// Returns: households ordered oldest first, error
func (s *Store) ListMoneyHouseholds(ctx context.Context, userID uuid.UUID) ([]MoneyHousehold, error) {
	rows, err := s.pool.Query(ctx, "SELECT sp.id, sm.role, (SELECT count(*) FROM space_members c WHERE c.space_id = sp.id), ms.currency, ms.locale, ms.shared_by_default, ms.approval_threshold_minor, ms.monthly_close_day, ms.updated_at FROM spaces sp JOIN space_members sm ON sm.space_id = sp.id AND sm.user_id = $1 JOIN money_settings ms ON ms.space_id = sp.id WHERE sp.deleted_at IS NULL ORDER BY sp.created_at ASC", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []MoneyHousehold
	for rows.Next() {
		var h MoneyHousehold
		if err := rows.Scan(&h.SpaceID, &h.Role, &h.MemberCount, &h.Settings.Currency, &h.Settings.Locale, &h.Settings.SharedByDefault, &h.Settings.ApprovalThresholdMinor, &h.Settings.MonthlyCloseDay, &h.Settings.UpdatedAt); err != nil {
			return nil, err
		}
		h.Settings.SpaceID = h.SpaceID
		out = append(out, h)
	}
	return out, rows.Err()
}

// MoneyRole resolves the caller's role on a money-enabled household.
//
// Membership and the money-enabled flag are checked in one statement rather than
// two middlewares, because every money route needs both and the ledger screens
// issue several requests per interaction.
// Args: ctx, spaceID, userID
// Returns: the role, ErrNotFound when the space does not exist, has money
// disabled, or the caller is not a member — the three are deliberately
// indistinguishable so a non-member cannot probe for which households exist
func (s *Store) MoneyRole(ctx context.Context, spaceID, userID uuid.UUID) (string, error) {
	var role string
	err := s.pool.QueryRow(ctx, "SELECT sm.role FROM space_members sm JOIN spaces sp ON sp.id = sm.space_id AND sp.deleted_at IS NULL JOIN money_settings ms ON ms.space_id = sm.space_id WHERE sm.space_id = $1 AND sm.user_id = $2", spaceID, userID).Scan(&role)
	if err != nil {
		if noRows(err) {
			return "", ErrNotFound
		}
		return "", err
	}
	return role, nil
}

const moneyCategoryColumns = `id, space_id, name, emoji, color, kind, sort_order, archived_at`

func scanMoneyCategory(row pgx.Row) (*MoneyCategory, error) {
	var c MoneyCategory
	if err := row.Scan(&c.ID, &c.SpaceID, &c.Name, &c.Emoji, &c.Color, &c.Kind, &c.SortOrder, &c.ArchivedAt); err != nil {
		if noRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &c, nil
}

// ListMoneyCategories returns a household's categories, archived ones last.
// Args: ctx, spaceID, includeArchived
// Returns: categories in display order, error
func (s *Store) ListMoneyCategories(ctx context.Context, spaceID uuid.UUID, includeArchived bool) ([]MoneyCategory, error) {
	query := "SELECT " + moneyCategoryColumns + " FROM money_categories WHERE space_id = $1 AND archived_at IS NULL ORDER BY sort_order ASC, name ASC"
	if includeArchived {
		query = "SELECT " + moneyCategoryColumns + " FROM money_categories WHERE space_id = $1 ORDER BY archived_at NULLS FIRST, sort_order ASC, name ASC"
	}
	rows, err := s.pool.Query(ctx, query, spaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []MoneyCategory
	for rows.Next() {
		var c MoneyCategory
		if err := rows.Scan(&c.ID, &c.SpaceID, &c.Name, &c.Emoji, &c.Color, &c.Kind, &c.SortOrder, &c.ArchivedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// CreateMoneyCategory adds a category to a household.
// Args: ctx, spaceID, name, emoji, color, kind ("expense"|"income"), sortOrder
// Returns: the created category, ErrConflict when the name is already used in
// this household (comparison is case-insensitive, so "Food" and "food" collide)
func (s *Store) CreateMoneyCategory(ctx context.Context, spaceID uuid.UUID, name, emoji, color, kind string, sortOrder int) (*MoneyCategory, error) {
	c, err := scanMoneyCategory(s.pool.QueryRow(ctx, "INSERT INTO money_categories (space_id, name, emoji, color, kind, sort_order) VALUES ($1, $2, $3, $4, $5, $6) RETURNING "+moneyCategoryColumns, spaceID, name, emoji, color, kind, sortOrder))
	if isUniqueViolation(err, "uq_money_categories_name") {
		return nil, ErrConflict
	}
	return c, err
}

// UpdateMoneyCategory applies a partial update, scoped to the household so one
// household can never rename another's category.
// Args: ctx, spaceID, categoryID, name/emoji/color/sortOrder/archived (nil skips)
// Returns: the updated category, ErrNotFound, ErrConflict on a name collision
func (s *Store) UpdateMoneyCategory(ctx context.Context, spaceID, categoryID uuid.UUID, name, emoji, color *string, sortOrder *int, archived *bool) (*MoneyCategory, error) {
	var archivedAt *time.Time
	if archived != nil && *archived {
		now := time.Now().UTC()
		archivedAt = &now
	}
	c, err := scanMoneyCategory(s.pool.QueryRow(ctx, "UPDATE money_categories SET name = COALESCE($3, name), emoji = COALESCE($4, emoji), color = COALESCE($5, color), sort_order = COALESCE($6, sort_order), archived_at = CASE WHEN $7::boolean IS NULL THEN archived_at WHEN $7::boolean THEN COALESCE(archived_at, $8) ELSE NULL END, updated_at = now() WHERE space_id = $1 AND id = $2 RETURNING "+moneyCategoryColumns, spaceID, categoryID, name, emoji, color, sortOrder, archived, archivedAt))
	if isUniqueViolation(err, "uq_money_categories_name") {
		return nil, ErrConflict
	}
	return c, err
}

const moneyAccountColumns = `id, space_id, name, kind, currency, opening_balance_minor, is_shared, owner_id, archived_at`

func scanMoneyAccount(row pgx.Row) (*MoneyAccount, error) {
	var a MoneyAccount
	if err := row.Scan(&a.ID, &a.SpaceID, &a.Name, &a.Kind, &a.Currency, &a.OpeningBalanceMinor, &a.IsShared, &a.OwnerID, &a.ArchivedAt); err != nil {
		if noRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &a, nil
}

// ListMoneyAccounts returns a household's live accounts.
// Args: ctx, spaceID
// Returns: accounts ordered by name, error
func (s *Store) ListMoneyAccounts(ctx context.Context, spaceID uuid.UUID) ([]MoneyAccount, error) {
	rows, err := s.pool.Query(ctx, "SELECT "+moneyAccountColumns+" FROM money_accounts WHERE space_id = $1 AND archived_at IS NULL ORDER BY name ASC", spaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []MoneyAccount
	for rows.Next() {
		var a MoneyAccount
		if err := rows.Scan(&a.ID, &a.SpaceID, &a.Name, &a.Kind, &a.Currency, &a.OpeningBalanceMinor, &a.IsShared, &a.OwnerID, &a.ArchivedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// CreateMoneyAccount adds an account to a household.
// Args: ctx, spaceID, name, kind, currency, openingBalanceMinor, isShared, ownerID
// Returns: the created account, error
func (s *Store) CreateMoneyAccount(ctx context.Context, spaceID uuid.UUID, name, kind, currency string, openingBalanceMinor int64, isShared bool, ownerID *uuid.UUID) (*MoneyAccount, error) {
	return scanMoneyAccount(s.pool.QueryRow(ctx, "INSERT INTO money_accounts (space_id, name, kind, currency, opening_balance_minor, is_shared, owner_id) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING "+moneyAccountColumns, spaceID, name, kind, currency, openingBalanceMinor, isShared, ownerID))
}

// UpdateMoneyAccount applies a partial update scoped to the household.
// Args: ctx, spaceID, accountID, name/kind/openingBalanceMinor/isShared/archived
// Returns: the updated account, ErrNotFound
func (s *Store) UpdateMoneyAccount(ctx context.Context, spaceID, accountID uuid.UUID, name, kind *string, openingBalanceMinor *int64, isShared, archived *bool) (*MoneyAccount, error) {
	var archivedAt *time.Time
	if archived != nil && *archived {
		now := time.Now().UTC()
		archivedAt = &now
	}
	return scanMoneyAccount(s.pool.QueryRow(ctx, "UPDATE money_accounts SET name = COALESCE($3, name), kind = COALESCE($4, kind), opening_balance_minor = COALESCE($5, opening_balance_minor), is_shared = COALESCE($6, is_shared), archived_at = CASE WHEN $7::boolean IS NULL THEN archived_at WHEN $7::boolean THEN COALESCE(archived_at, $8) ELSE NULL END, updated_at = now() WHERE space_id = $1 AND id = $2 RETURNING "+moneyAccountColumns, spaceID, accountID, name, kind, openingBalanceMinor, isShared, archived, archivedAt))
}

const moneyTransactionColumns = `id, space_id, client_id, account_id, category_id, type, amount_minor, currency, occurred_on, note, is_shared, paid_by, created_by, created_at, updated_at`

func scanMoneyTransaction(row pgx.Row) (*MoneyTransaction, error) {
	var t MoneyTransaction
	if err := row.Scan(&t.ID, &t.SpaceID, &t.ClientID, &t.AccountID, &t.CategoryID, &t.Type, &t.AmountMinor, &t.Currency, &t.OccurredOn, &t.Note, &t.IsShared, &t.PaidBy, &t.CreatedBy, &t.CreatedAt, &t.UpdatedAt); err != nil {
		if noRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &t, nil
}

// TransactionFilter narrows a ledger read. From and To are inclusive calendar
// dates rather than timestamps: an entry belongs to the day the household says
// it happened, which must not shift because a member is travelling.
type TransactionFilter struct {
	SpaceID uuid.UUID
	From    *time.Time
	To      *time.Time
	Search  string
	PaidBy  *uuid.UUID
	Limit   int
	Cursor  string
}

// CreateMoneyTransaction appends an entry to the ledger.
// Args: ctx, transaction (ClientID must be set by the caller)
// Returns: the stored transaction, error
// Handles: a retried request, which returns the transaction the first attempt
// created instead of duplicating it — the client mints ClientID once per entry,
// so a lost response never charges the household twice
// Handles: a category belonging to another household, rejected as ErrForbidden
// rather than silently linking across households
func (s *Store) CreateMoneyTransaction(ctx context.Context, t MoneyTransaction) (*MoneyTransaction, error) {
	var categorySpace uuid.UUID
	err := s.pool.QueryRow(ctx, "SELECT space_id FROM money_categories WHERE id = $1", t.CategoryID).Scan(&categorySpace)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return nil, ErrNotFound
	case err != nil:
		return nil, err
	case categorySpace != t.SpaceID:
		return nil, ErrForbidden
	}

	if t.AccountID != nil {
		var accountSpace uuid.UUID
		err := s.pool.QueryRow(ctx, "SELECT space_id FROM money_accounts WHERE id = $1", *t.AccountID).Scan(&accountSpace)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			return nil, ErrNotFound
		case err != nil:
			return nil, err
		case accountSpace != t.SpaceID:
			return nil, ErrForbidden
		}
	}

	created, err := scanMoneyTransaction(s.pool.QueryRow(ctx, "INSERT INTO money_transactions (space_id, client_id, account_id, category_id, type, amount_minor, currency, occurred_on, note, is_shared, paid_by, created_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) ON CONFLICT (space_id, client_id) DO NOTHING RETURNING "+moneyTransactionColumns, t.SpaceID, t.ClientID, t.AccountID, t.CategoryID, t.Type, t.AmountMinor, t.Currency, t.OccurredOn, t.Note, t.IsShared, t.PaidBy, t.CreatedBy))
	if err == nil {
		return created, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	return scanMoneyTransaction(s.pool.QueryRow(ctx, "SELECT "+moneyTransactionColumns+" FROM money_transactions WHERE space_id = $1 AND client_id = $2", t.SpaceID, t.ClientID))
}

// ListMoneyTransactions reads the ledger feed newest first.
// Args: ctx, filter
// Returns: the page of transactions, the cursor for the next page (empty when
// the walk is complete), error
// Handles: a malformed cursor, rejected as ErrConflict rather than silently
// restarting the walk from the top and re-showing entries the client already has
func (s *Store) ListMoneyTransactions(ctx context.Context, f TransactionFilter) ([]MoneyTransaction, string, error) {
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 100
	}

	clauses := []string{"space_id = $1", "deleted_at IS NULL"}
	args := []any{f.SpaceID}

	if f.From != nil {
		args = append(args, *f.From)
		clauses = append(clauses, fmt.Sprintf("occurred_on >= $%d", len(args)))
	}
	if f.To != nil {
		args = append(args, *f.To)
		clauses = append(clauses, fmt.Sprintf("occurred_on <= $%d", len(args)))
	}
	if f.PaidBy != nil {
		args = append(args, *f.PaidBy)
		clauses = append(clauses, fmt.Sprintf("paid_by = $%d", len(args)))
	}
	if search := strings.TrimSpace(f.Search); search != "" {
		args = append(args, "%"+search+"%")
		clauses = append(clauses, fmt.Sprintf("(note ILIKE $%d OR category_id IN (SELECT id FROM money_categories WHERE space_id = money_transactions.space_id AND name ILIKE $%d))", len(args), len(args)))
	}
	if f.Cursor != "" {
		cursorDate, cursorID, err := decodeTransactionCursor(f.Cursor)
		if err != nil {
			return nil, "", err
		}
		args = append(args, cursorDate, cursorID)
		clauses = append(clauses, fmt.Sprintf("(occurred_on, id) < ($%d, $%d)", len(args)-1, len(args)))
	}

	args = append(args, f.Limit+1)
	query := "SELECT " + moneyTransactionColumns + " FROM money_transactions WHERE " + strings.Join(clauses, " AND ") + " ORDER BY occurred_on DESC, id DESC LIMIT $" + fmt.Sprint(len(args))

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()

	var out []MoneyTransaction
	for rows.Next() {
		var t MoneyTransaction
		if err := rows.Scan(&t.ID, &t.SpaceID, &t.ClientID, &t.AccountID, &t.CategoryID, &t.Type, &t.AmountMinor, &t.Currency, &t.OccurredOn, &t.Note, &t.IsShared, &t.PaidBy, &t.CreatedBy, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, "", err
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}

	next := ""
	if len(out) > f.Limit {
		out = out[:f.Limit]
		last := out[len(out)-1]
		next = encodeTransactionCursor(last.OccurredOn, last.ID)
	}
	return out, next, nil
}

// encodeTransactionCursor packs the keyset position into one opaque token.
func encodeTransactionCursor(occurredOn time.Time, id uuid.UUID) string {
	return base64.RawURLEncoding.EncodeToString([]byte(occurredOn.Format("2006-01-02") + "|" + id.String()))
}

// decodeTransactionCursor unpacks a keyset cursor.
// Args: raw (the opaque token from a previous page)
// Returns: the date and id to page from, ErrConflict when the token is
// unreadable
func decodeTransactionCursor(raw string) (time.Time, uuid.UUID, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return time.Time{}, uuid.Nil, ErrConflict
	}
	parts := strings.SplitN(string(decoded), "|", 2)
	if len(parts) != 2 {
		return time.Time{}, uuid.Nil, ErrConflict
	}
	date, err := time.Parse("2006-01-02", parts[0])
	if err != nil {
		return time.Time{}, uuid.Nil, ErrConflict
	}
	id, err := uuid.Parse(parts[1])
	if err != nil {
		return time.Time{}, uuid.Nil, ErrConflict
	}
	return date, id, nil
}

// UpdateMoneyTransaction applies a partial update to a live entry.
// Args: ctx, spaceID, transactionID, categoryID/accountID/amountMinor/
// occurredOn/note/isShared/paidBy (nil leaves the field untouched)
// Returns: the updated transaction, ErrNotFound when it is missing or deleted
func (s *Store) UpdateMoneyTransaction(ctx context.Context, spaceID, transactionID uuid.UUID, categoryID, accountID *uuid.UUID, amountMinor *int64, occurredOn *time.Time, note *string, isShared *bool, paidBy *uuid.UUID) (*MoneyTransaction, error) {
	if categoryID != nil {
		var categorySpace uuid.UUID
		err := s.pool.QueryRow(ctx, "SELECT space_id FROM money_categories WHERE id = $1", *categoryID).Scan(&categorySpace)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			return nil, ErrNotFound
		case err != nil:
			return nil, err
		case categorySpace != spaceID:
			return nil, ErrForbidden
		}
	}
	return scanMoneyTransaction(s.pool.QueryRow(ctx, "UPDATE money_transactions SET category_id = COALESCE($3, category_id), account_id = COALESCE($4, account_id), amount_minor = COALESCE($5, amount_minor), occurred_on = COALESCE($6, occurred_on), note = COALESCE($7, note), is_shared = COALESCE($8, is_shared), paid_by = COALESCE($9, paid_by), updated_at = now() WHERE space_id = $1 AND id = $2 AND deleted_at IS NULL RETURNING "+moneyTransactionColumns, spaceID, transactionID, categoryID, accountID, amountMinor, occurredOn, note, isShared, paidBy))
}

// DeleteMoneyTransaction soft-deletes an entry.
//
// The row is kept rather than removed so a member who deletes an entry the rest
// of the household has already reconciled against leaves a trace, and so a
// replayed create cannot resurrect it under the same client id.
// Args: ctx, spaceID, transactionID
// Returns: error, ErrNotFound when nothing live matched
func (s *Store) DeleteMoneyTransaction(ctx context.Context, spaceID, transactionID uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, "UPDATE money_transactions SET deleted_at = now(), updated_at = now() WHERE space_id = $1 AND id = $2 AND deleted_at IS NULL", spaceID, transactionID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// MoneyTotals is the headline arithmetic for a period.
type MoneyTotals struct {
	SpentMinor  int64
	IncomeMinor int64
	Count       int
}

// CategoryTotal is one slice of the spending breakdown.
type CategoryTotal struct {
	CategoryID  uuid.UUID
	Name        string
	Emoji       string
	Color       string
	AmountMinor int64
	Count       int
}

// MemberTotal is one member's contribution, used by both the member bars and
// the settle-up calculation.
type MemberTotal struct {
	UserID           *uuid.UUID
	Name             string
	AmountMinor      int64
	SharedSpentMinor int64
}

// DayTotal is one column of the daily spending series.
type DayTotal struct {
	Day         time.Time
	AmountMinor int64
}

// MoneySummary is every aggregate the insights screen renders, computed in one
// round trip. These are deliberately server-side: a household's full history is
// unbounded, and paging it to the client only to add it up there would get
// slower every month.
type MoneySummary struct {
	Totals     MoneyTotals
	Categories []CategoryTotal
	Members    []MemberTotal
	Days       []DayTotal
}

// MoneySummaryFor computes the period aggregates for a household.
// Args: ctx, spaceID, from, to (inclusive dates), paidBy (nil for the whole
// household, set to scope the figures to one member)
// Returns: the summary, error
// Handles: a period with no entries, which returns zeroed totals and empty
// slices rather than an error
func (s *Store) MoneySummaryFor(ctx context.Context, spaceID uuid.UUID, from, to time.Time, paidBy *uuid.UUID) (*MoneySummary, error) {
	summary := &MoneySummary{}

	if err := s.pool.QueryRow(ctx, "SELECT COALESCE(sum(amount_minor) FILTER (WHERE type = 'expense'), 0), COALESCE(sum(amount_minor) FILTER (WHERE type = 'income'), 0), count(*) FROM money_transactions WHERE space_id = $1 AND deleted_at IS NULL AND occurred_on BETWEEN $2 AND $3 AND ($4::uuid IS NULL OR paid_by = $4)", spaceID, from, to, paidBy).Scan(&summary.Totals.SpentMinor, &summary.Totals.IncomeMinor, &summary.Totals.Count); err != nil {
		return nil, err
	}

	categoryRows, err := s.pool.Query(ctx, "SELECT c.id, c.name, c.emoji, c.color, sum(t.amount_minor), count(*) FROM money_transactions t JOIN money_categories c ON c.id = t.category_id WHERE t.space_id = $1 AND t.deleted_at IS NULL AND t.type = 'expense' AND t.occurred_on BETWEEN $2 AND $3 AND ($4::uuid IS NULL OR t.paid_by = $4) GROUP BY c.id, c.name, c.emoji, c.color ORDER BY sum(t.amount_minor) DESC", spaceID, from, to, paidBy)
	if err != nil {
		return nil, err
	}
	defer categoryRows.Close()
	for categoryRows.Next() {
		var c CategoryTotal
		if err := categoryRows.Scan(&c.CategoryID, &c.Name, &c.Emoji, &c.Color, &c.AmountMinor, &c.Count); err != nil {
			return nil, err
		}
		summary.Categories = append(summary.Categories, c)
	}
	if err := categoryRows.Err(); err != nil {
		return nil, err
	}

	memberRows, err := s.pool.Query(ctx, "SELECT t.paid_by, COALESCE(u.name, ''), sum(t.amount_minor), COALESCE(sum(t.amount_minor) FILTER (WHERE t.is_shared), 0) FROM money_transactions t LEFT JOIN users u ON u.id = t.paid_by WHERE t.space_id = $1 AND t.deleted_at IS NULL AND t.type = 'expense' AND t.occurred_on BETWEEN $2 AND $3 GROUP BY t.paid_by, u.name ORDER BY sum(t.amount_minor) DESC", spaceID, from, to)
	if err != nil {
		return nil, err
	}
	defer memberRows.Close()
	for memberRows.Next() {
		var m MemberTotal
		if err := memberRows.Scan(&m.UserID, &m.Name, &m.AmountMinor, &m.SharedSpentMinor); err != nil {
			return nil, err
		}
		summary.Members = append(summary.Members, m)
	}
	if err := memberRows.Err(); err != nil {
		return nil, err
	}

	dayRows, err := s.pool.Query(ctx, "SELECT occurred_on, sum(amount_minor) FROM money_transactions WHERE space_id = $1 AND deleted_at IS NULL AND type = 'expense' AND occurred_on BETWEEN $2 AND $3 AND ($4::uuid IS NULL OR paid_by = $4) GROUP BY occurred_on ORDER BY occurred_on ASC", spaceID, from, to, paidBy)
	if err != nil {
		return nil, err
	}
	defer dayRows.Close()
	for dayRows.Next() {
		var d DayTotal
		if err := dayRows.Scan(&d.Day, &d.AmountMinor); err != nil {
			return nil, err
		}
		summary.Days = append(summary.Days, d)
	}
	return summary, dayRows.Err()
}

const moneyBudgetColumns = `id, space_id, category_id, period, limit_minor, starts_on`

// BudgetUsage pairs a budget with what has been spent against it this month.
type BudgetUsage struct {
	Budget    MoneyBudget
	Name      string
	Emoji     string
	Color     string
	UsedMinor int64
}

// ListMoneyBudgets returns every budget with its usage over the given period.
// Args: ctx, spaceID, from, to (the month being measured)
// Returns: budgets with usage, ordered by limit descending, error
func (s *Store) ListMoneyBudgets(ctx context.Context, spaceID uuid.UUID, from, to time.Time) ([]BudgetUsage, error) {
	rows, err := s.pool.Query(ctx, "SELECT b.id, b.space_id, b.category_id, b.period, b.limit_minor, b.starts_on, c.name, c.emoji, c.color, COALESCE((SELECT sum(t.amount_minor) FROM money_transactions t WHERE t.space_id = b.space_id AND t.category_id = b.category_id AND t.deleted_at IS NULL AND t.type = 'expense' AND t.occurred_on BETWEEN $2 AND $3), 0) FROM money_budgets b JOIN money_categories c ON c.id = b.category_id WHERE b.space_id = $1 ORDER BY b.limit_minor DESC", spaceID, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []BudgetUsage
	for rows.Next() {
		var u BudgetUsage
		if err := rows.Scan(&u.Budget.ID, &u.Budget.SpaceID, &u.Budget.CategoryID, &u.Budget.Period, &u.Budget.LimitMinor, &u.Budget.StartsOn, &u.Name, &u.Emoji, &u.Color, &u.UsedMinor); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// UpsertMoneyBudget sets the monthly ceiling for one category.
// Args: ctx, spaceID, categoryID, limitMinor
// Returns: the stored budget, ErrForbidden when the category belongs to another
// household, ErrNotFound when it does not exist
func (s *Store) UpsertMoneyBudget(ctx context.Context, spaceID, categoryID uuid.UUID, limitMinor int64) (*MoneyBudget, error) {
	var categorySpace uuid.UUID
	err := s.pool.QueryRow(ctx, "SELECT space_id FROM money_categories WHERE id = $1", categoryID).Scan(&categorySpace)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return nil, ErrNotFound
	case err != nil:
		return nil, err
	case categorySpace != spaceID:
		return nil, ErrForbidden
	}

	var b MoneyBudget
	if err := s.pool.QueryRow(ctx, "INSERT INTO money_budgets (space_id, category_id, limit_minor) VALUES ($1, $2, $3) ON CONFLICT (space_id, category_id, period) DO UPDATE SET limit_minor = EXCLUDED.limit_minor, updated_at = now() RETURNING "+moneyBudgetColumns, spaceID, categoryID, limitMinor).Scan(&b.ID, &b.SpaceID, &b.CategoryID, &b.Period, &b.LimitMinor, &b.StartsOn); err != nil {
		return nil, err
	}
	return &b, nil
}

// DeleteMoneyBudget removes a category ceiling.
// Args: ctx, spaceID, budgetID
// Returns: error, ErrNotFound when nothing matched
func (s *Store) DeleteMoneyBudget(ctx context.Context, spaceID, budgetID uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, "DELETE FROM money_budgets WHERE space_id = $1 AND id = $2", spaceID, budgetID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

const moneyBillColumns = `id, space_id, name, emoji, category_id, account_id, amount_minor, day_of_month, auto_log, is_shared, paid_by, last_logged_on, archived_at`

func scanMoneyBill(row pgx.Row) (*MoneyBill, error) {
	var b MoneyBill
	if err := row.Scan(&b.ID, &b.SpaceID, &b.Name, &b.Emoji, &b.CategoryID, &b.AccountID, &b.AmountMinor, &b.DayOfMonth, &b.AutoLog, &b.IsShared, &b.PaidBy, &b.LastLoggedOn, &b.ArchivedAt); err != nil {
		if noRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &b, nil
}

// ListMoneyBills returns a household's live recurring charges, due-date order.
// Args: ctx, spaceID
// Returns: bills, error
func (s *Store) ListMoneyBills(ctx context.Context, spaceID uuid.UUID) ([]MoneyBill, error) {
	rows, err := s.pool.Query(ctx, "SELECT "+moneyBillColumns+" FROM money_bills WHERE space_id = $1 AND archived_at IS NULL ORDER BY day_of_month ASC, name ASC", spaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []MoneyBill
	for rows.Next() {
		var b MoneyBill
		if err := rows.Scan(&b.ID, &b.SpaceID, &b.Name, &b.Emoji, &b.CategoryID, &b.AccountID, &b.AmountMinor, &b.DayOfMonth, &b.AutoLog, &b.IsShared, &b.PaidBy, &b.LastLoggedOn, &b.ArchivedAt); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// CreateMoneyBill adds a recurring charge.
// Args: ctx, bill (SpaceID, Name, AmountMinor and DayOfMonth required)
// Returns: the created bill, error
func (s *Store) CreateMoneyBill(ctx context.Context, b MoneyBill) (*MoneyBill, error) {
	return scanMoneyBill(s.pool.QueryRow(ctx, "INSERT INTO money_bills (space_id, name, emoji, category_id, account_id, amount_minor, day_of_month, auto_log, is_shared, paid_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING "+moneyBillColumns, b.SpaceID, b.Name, b.Emoji, b.CategoryID, b.AccountID, b.AmountMinor, b.DayOfMonth, b.AutoLog, b.IsShared, b.PaidBy))
}

// UpdateMoneyBill applies a partial update scoped to the household.
// Args: ctx, spaceID, billID, name/emoji/amountMinor/dayOfMonth/autoLog/archived
// Returns: the updated bill, ErrNotFound
func (s *Store) UpdateMoneyBill(ctx context.Context, spaceID, billID uuid.UUID, name, emoji *string, amountMinor *int64, dayOfMonth *int, autoLog, archived *bool) (*MoneyBill, error) {
	var archivedAt *time.Time
	if archived != nil && *archived {
		now := time.Now().UTC()
		archivedAt = &now
	}
	return scanMoneyBill(s.pool.QueryRow(ctx, "UPDATE money_bills SET name = COALESCE($3, name), emoji = COALESCE($4, emoji), amount_minor = COALESCE($5, amount_minor), day_of_month = COALESCE($6, day_of_month), auto_log = COALESCE($7, auto_log), archived_at = CASE WHEN $8::boolean IS NULL THEN archived_at WHEN $8::boolean THEN COALESCE(archived_at, $9) ELSE NULL END, updated_at = now() WHERE space_id = $1 AND id = $2 RETURNING "+moneyBillColumns, spaceID, billID, name, emoji, amountMinor, dayOfMonth, autoLog, archived, archivedAt))
}

const moneyHoldingColumns = `id, space_id, owner_id, name, badge, asset_type, units::text, avg_cost_minor, last_price_minor, day_change_bps, sip_minor, currency, color, priced_at, archived_at`

func scanMoneyHolding(row pgx.Row) (*MoneyHolding, error) {
	var h MoneyHolding
	if err := row.Scan(&h.ID, &h.SpaceID, &h.OwnerID, &h.Name, &h.Badge, &h.AssetType, &h.Units, &h.AvgCostMinor, &h.LastPriceMinor, &h.DayChangeBps, &h.SIPMinor, &h.Currency, &h.Color, &h.PricedAt, &h.ArchivedAt); err != nil {
		if noRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &h, nil
}

// ListMoneyHoldings returns a household's live investment positions.
//
// Position value is not computed here. units × price overflows int64 for a large
// enough holding, and rounding it in SQL would fix the rounding rule in the
// wrong layer; the API layer multiplies exact decimals instead.
// Args: ctx, spaceID
// Returns: holdings ordered by name, error
func (s *Store) ListMoneyHoldings(ctx context.Context, spaceID uuid.UUID) ([]MoneyHolding, error) {
	rows, err := s.pool.Query(ctx, "SELECT "+moneyHoldingColumns+" FROM money_holdings WHERE space_id = $1 AND archived_at IS NULL ORDER BY name ASC", spaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []MoneyHolding
	for rows.Next() {
		var h MoneyHolding
		if err := rows.Scan(&h.ID, &h.SpaceID, &h.OwnerID, &h.Name, &h.Badge, &h.AssetType, &h.Units, &h.AvgCostMinor, &h.LastPriceMinor, &h.DayChangeBps, &h.SIPMinor, &h.Currency, &h.Color, &h.PricedAt, &h.ArchivedAt); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// CreateMoneyHolding adds an investment position.
// Args: ctx, holding (Units is a decimal string, validated by the caller)
// Returns: the created holding, error
func (s *Store) CreateMoneyHolding(ctx context.Context, h MoneyHolding) (*MoneyHolding, error) {
	return scanMoneyHolding(s.pool.QueryRow(ctx, "INSERT INTO money_holdings (space_id, owner_id, name, badge, asset_type, units, avg_cost_minor, last_price_minor, day_change_bps, sip_minor, currency, color, priced_at) VALUES ($1, $2, $3, $4, $5, $6::numeric, $7, $8, $9, $10, $11, $12, now()) RETURNING "+moneyHoldingColumns, h.SpaceID, h.OwnerID, h.Name, h.Badge, h.AssetType, h.Units, h.AvgCostMinor, h.LastPriceMinor, h.DayChangeBps, h.SIPMinor, h.Currency, h.Color))
}

// UpdateMoneyHolding applies a partial update scoped to the household.
// Args: ctx, spaceID, holdingID, units/avgCostMinor/lastPriceMinor/
// dayChangeBps/sipMinor/archived (nil leaves the field untouched)
// Returns: the updated holding, ErrNotFound
// Handles: a price update, which restamps priced_at so a stale quote is visible
func (s *Store) UpdateMoneyHolding(ctx context.Context, spaceID, holdingID uuid.UUID, units *string, avgCostMinor, lastPriceMinor *int64, dayChangeBps *int, sipMinor *int64, archived *bool) (*MoneyHolding, error) {
	var archivedAt *time.Time
	if archived != nil && *archived {
		now := time.Now().UTC()
		archivedAt = &now
	}
	return scanMoneyHolding(s.pool.QueryRow(ctx, "UPDATE money_holdings SET units = COALESCE($3::numeric, units), avg_cost_minor = COALESCE($4, avg_cost_minor), last_price_minor = COALESCE($5, last_price_minor), day_change_bps = COALESCE($6, day_change_bps), sip_minor = COALESCE($7, sip_minor), priced_at = CASE WHEN $5::bigint IS NULL THEN priced_at ELSE now() END, archived_at = CASE WHEN $8::boolean IS NULL THEN archived_at WHEN $8::boolean THEN COALESCE(archived_at, $9) ELSE NULL END, updated_at = now() WHERE space_id = $1 AND id = $2 RETURNING "+moneyHoldingColumns, spaceID, holdingID, units, avgCostMinor, lastPriceMinor, dayChangeBps, sipMinor, archived, archivedAt))
}

const moneyInviteColumns = `id, space_id, email, role, invited_by, expires_at, accepted_at, created_at`

func scanMoneyInvite(row pgx.Row) (*MoneyInvite, error) {
	var i MoneyInvite
	if err := row.Scan(&i.ID, &i.SpaceID, &i.Email, &i.Role, &i.InvitedBy, &i.ExpiresAt, &i.AcceptedAt, &i.CreatedAt); err != nil {
		if noRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &i, nil
}

// ListMoneyInvites returns the household's outstanding invitations.
// Args: ctx, spaceID
// Returns: open, unexpired invites, error
func (s *Store) ListMoneyInvites(ctx context.Context, spaceID uuid.UUID) ([]MoneyInvite, error) {
	rows, err := s.pool.Query(ctx, "SELECT "+moneyInviteColumns+" FROM money_invites WHERE space_id = $1 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > now() ORDER BY created_at DESC", spaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []MoneyInvite
	for rows.Next() {
		var i MoneyInvite
		if err := rows.Scan(&i.ID, &i.SpaceID, &i.Email, &i.Role, &i.InvitedBy, &i.ExpiresAt, &i.AcceptedAt, &i.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// CreateMoneyInvite records an invitation and stores only the hash of its token.
// Args: ctx, spaceID, email, role, tokenHash (32 bytes), invitedBy, expiresAt
// Returns: the invite, ErrConflict when this email already has an open invite to
// this household — re-inviting is a no-op the caller should report as success
func (s *Store) CreateMoneyInvite(ctx context.Context, spaceID uuid.UUID, email, role string, tokenHash []byte, invitedBy uuid.UUID, expiresAt time.Time) (*MoneyInvite, error) {
	i, err := scanMoneyInvite(s.pool.QueryRow(ctx, "INSERT INTO money_invites (space_id, email, role, token_hash, invited_by, expires_at) VALUES ($1, $2, $3, $4, $5, $6) RETURNING "+moneyInviteColumns, spaceID, email, role, tokenHash, invitedBy, expiresAt))
	if isUniqueViolation(err, "uq_money_invites_open") {
		return nil, ErrConflict
	}
	return i, err
}

// RevokeMoneyInvite withdraws an outstanding invitation.
// Args: ctx, spaceID, inviteID
// Returns: error, ErrNotFound when nothing open matched
func (s *Store) RevokeMoneyInvite(ctx context.Context, spaceID, inviteID uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, "UPDATE money_invites SET revoked_at = now() WHERE space_id = $1 AND id = $2 AND accepted_at IS NULL AND revoked_at IS NULL", spaceID, inviteID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// AcceptMoneyInvite redeems an invitation token and adds the caller to the
// household, in one transaction so a redeemed token can never be spent twice.
//
// The invite's email is not checked against the caller's: the token is the
// capability, and requiring both would lock out anyone whose Google address
// differs from the one a family member typed. Expiry and single use are what
// bound it.
// Args: ctx, tokenHash (32 bytes), userID
// Returns: the space joined, error
// Handles: an unknown, expired, revoked or already-redeemed token, all
// ErrNotFound so none of them can be told apart by probing; a caller who is
// already a member, whose existing role is kept rather than downgraded
func (s *Store) AcceptMoneyInvite(ctx context.Context, tokenHash []byte, userID uuid.UUID) (uuid.UUID, error) {
	var spaceID uuid.UUID
	err := s.tx(ctx, func(tx pgx.Tx) error {
		var inviteID uuid.UUID
		var role string
		err := tx.QueryRow(ctx, "SELECT id, space_id, role FROM money_invites WHERE token_hash = $1 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > now() FOR UPDATE", tokenHash).Scan(&inviteID, &spaceID, &role)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if _, err := tx.Exec(ctx, "INSERT INTO space_members (space_id, user_id, role) VALUES ($1, $2, $3) ON CONFLICT (space_id, user_id) DO NOTHING", spaceID, userID, role); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, "UPDATE money_invites SET accepted_at = now(), accepted_by = $2 WHERE id = $1", inviteID, userID)
		return err
	})
	if err != nil {
		return uuid.Nil, err
	}
	return spaceID, nil
}
