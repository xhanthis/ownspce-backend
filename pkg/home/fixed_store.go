package home

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// MaxFixedRows caps one month-range read: 13 months of up to 200 items each is far beyond a household.
const MaxFixedRows = 2600

// FixedItem is something that happens every month and belongs to no particular day: rent, the maid, a salary,
// a SIP. It shows in every month from StartsOn up to EndsOn (nil = still running). Amounts are in paise.
type FixedItem struct {
	ID          uuid.UUID  `json:"id"`
	Name        string     `json:"name"`
	Kind        string     `json:"kind"`
	AmountMinor int64      `json:"amountMinor"`
	OwnerID     *uuid.UUID `json:"ownerId"`
	CategoryID  *uuid.UUID `json:"categoryId"`
	DueDay      *int       `json:"dueDay"`
	StartsOn    string     `json:"startsOn"`
	EndsOn      *string    `json:"endsOn"`
	SortOrder   int        `json:"sortOrder"`
}

// FixedPayment is one month's tick on one item: what was actually paid, when, by whom, and whether a proof is attached.
type FixedPayment struct {
	ID          uuid.UUID  `json:"id"`
	ItemID      uuid.UUID  `json:"itemId"`
	Month       string     `json:"month"`
	AmountMinor int64      `json:"amountMinor"`
	PaidOn      string     `json:"paidOn"`
	PaidBy      *uuid.UUID `json:"paidBy"`
	Note        string     `json:"note"`
	ProofType   string     `json:"proofType"`
}

// FixedRow is an item as one month sees it: the item plus that month's payment, if any.
type FixedRow struct {
	FixedItem
	Payment *FixedPayment `json:"payment"`
}

// FixedMonth is every live item for one month, in kind then household order.
type FixedMonth struct {
	Month string     `json:"month"`
	Items []FixedRow `json:"items"`
}

// FixedProof is an attached bill or receipt.
type FixedProof struct {
	MediaType string
	Bytes     []byte
}

// FixedMonths lists the live items for every month from first to last (both "YYYY-MM"), with that month's payment.
// Months with nothing live still appear, empty, so the app can draw them.
// Returns: one FixedMonth per month in order; ErrInvalid when the range is backwards or longer than 13 months
func (s *Store) FixedMonths(ctx context.Context, first, last string) ([]FixedMonth, error) {
	from, errFrom := time.Parse("2006-01", first)
	to, errTo := time.Parse("2006-01", last)
	if errFrom != nil || errTo != nil || to.Before(from) || to.After(from.AddDate(1, 0, 0)) {
		return nil, ErrInvalid
	}
	rows, err := s.pool.Query(ctx, "SELECT to_char(m.month, 'YYYY-MM'), i.id, i.name, i.kind, i.amount_minor, i.owner_id, i.category_id, i.due_day, to_char(i.starts_on, 'YYYY-MM'), to_char(i.ends_on, 'YYYY-MM'), i.sort_order, p.id, p.amount_minor, to_char(p.paid_on, 'YYYY-MM-DD'), p.paid_by, p.note, coalesce(pr.media_type, '') FROM generate_series($1::date, $2::date, interval '1 month') AS m(month) JOIN home_fixed_items i ON i.starts_on <= m.month::date AND (i.ends_on IS NULL OR i.ends_on >= m.month::date) LEFT JOIN home_fixed_payments p ON p.item_id = i.id AND p.month = m.month::date LEFT JOIN home_fixed_proofs pr ON pr.payment_id = p.id ORDER BY m.month, CASE i.kind WHEN 'expense' THEN 0 WHEN 'income' THEN 1 ELSE 2 END, i.sort_order, i.created_at, i.id LIMIT $3", from, to, MaxFixedRows)
	if err != nil {
		return nil, fmt.Errorf("list fixed: %w", err)
	}
	defer rows.Close()
	months := make([]FixedMonth, 0, 13)
	for cursor := from; !cursor.After(to); cursor = cursor.AddDate(0, 1, 0) {
		months = append(months, FixedMonth{Month: cursor.Format("2006-01"), Items: []FixedRow{}})
	}
	byMonth := map[string]*FixedMonth{}
	for index := range months {
		byMonth[months[index].Month] = &months[index]
	}
	for rows.Next() {
		var month, proofType string
		var row FixedRow
		var paymentID, paidBy *uuid.UUID
		var paidMinor *int64
		var paidOn, note *string
		if err := rows.Scan(&month, &row.ID, &row.Name, &row.Kind, &row.AmountMinor, &row.OwnerID, &row.CategoryID, &row.DueDay, &row.StartsOn, &row.EndsOn, &row.SortOrder, &paymentID, &paidMinor, &paidOn, &paidBy, &note, &proofType); err != nil {
			return nil, fmt.Errorf("scan fixed: %w", err)
		}
		if paymentID != nil {
			row.Payment = &FixedPayment{ID: *paymentID, ItemID: row.ID, Month: month, AmountMinor: *paidMinor, PaidOn: *paidOn, PaidBy: paidBy, Note: *note, ProofType: proofType}
		}
		if target, ok := byMonth[month]; ok {
			target.Items = append(target.Items, row)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read fixed: %w", err)
	}
	return months, nil
}

// HoldingsSipMinor sums the monthly SIP figure on every holding, so Insights can show when it differs from the fixed investments.
func (s *Store) HoldingsSipMinor(ctx context.Context) (int64, error) {
	var total int64
	if err := s.pool.QueryRow(ctx, "SELECT coalesce(sum(sip_minor), 0) FROM home_holdings").Scan(&total); err != nil {
		return 0, fmt.Errorf("sum sips: %w", err)
	}
	return total, nil
}

func scanFixedItem(row pgx.CollectableRow) (FixedItem, error) {
	var item FixedItem
	err := row.Scan(&item.ID, &item.Name, &item.Kind, &item.AmountMinor, &item.OwnerID, &item.CategoryID, &item.DueDay, &item.StartsOn, &item.EndsOn, &item.SortOrder)
	return item, err
}

// SaveFixedItem creates an item (id nil) or replaces one. A category must be an expense category. Moving the start
// past an archived end pulls the end along, so the item never ends before it starts.
// Returns: the stored item; ErrInvalid when the owner is not a member or the category is not an expense one; ErrNotFound on a missing id
func (s *Store) SaveFixedItem(ctx context.Context, id *uuid.UUID, item FixedItem, actor uuid.UUID) (FixedItem, error) {
	if item.CategoryID != nil {
		kind, err := s.categoryKind(ctx, *item.CategoryID)
		if err != nil {
			return FixedItem{}, err
		}
		if kind != "expense" {
			return FixedItem{}, ErrInvalid
		}
	}
	startsOn, err := time.Parse("2006-01", item.StartsOn)
	if err != nil {
		return FixedItem{}, ErrInvalid
	}
	var rows pgx.Rows
	if id == nil {
		rows, err = s.pool.Query(ctx, "INSERT INTO home_fixed_items (id, name, kind, amount_minor, owner_id, category_id, due_day, starts_on, sort_order, created_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::date, (SELECT coalesce(max(sort_order) + 1, 0) FROM home_fixed_items), $9) RETURNING id, name, kind, amount_minor, owner_id, category_id, due_day, to_char(starts_on, 'YYYY-MM'), to_char(ends_on, 'YYYY-MM'), sort_order", uuid.New(), item.Name, item.Kind, item.AmountMinor, item.OwnerID, item.CategoryID, item.DueDay, startsOn, actor)
	} else {
		rows, err = s.pool.Query(ctx, "UPDATE home_fixed_items SET name = $2, kind = $3, amount_minor = $4, owner_id = $5, category_id = $6, due_day = $7, starts_on = $8::date, ends_on = CASE WHEN ends_on IS NULL OR ends_on >= $8::date THEN ends_on ELSE $8::date END, updated_at = now() WHERE id = $1 RETURNING id, name, kind, amount_minor, owner_id, category_id, due_day, to_char(starts_on, 'YYYY-MM'), to_char(ends_on, 'YYYY-MM'), sort_order", *id, item.Name, item.Kind, item.AmountMinor, item.OwnerID, item.CategoryID, item.DueDay, startsOn)
	}
	if err != nil {
		return FixedItem{}, fmt.Errorf("save fixed item: %w", err)
	}
	saved, err := pgx.CollectOneRow(rows, scanFixedItem)
	if errors.Is(err, pgx.ErrNoRows) {
		return FixedItem{}, ErrNotFound
	}
	if isCode(err, "23503") || isCode(err, "23514") {
		return FixedItem{}, ErrInvalid
	}
	if err != nil {
		return FixedItem{}, fmt.Errorf("save fixed item: %w", err)
	}
	return saved, nil
}

// ArchiveFixedItem stops an item from the month given ("YYYY-MM"). An item that was never paid is deleted outright;
// one with history keeps it: it ends on that month when that month is paid, otherwise on the month before.
// Returns: ErrNotFound when there is no such item; ErrInvalid for a bad month
func (s *Store) ArchiveFixedItem(ctx context.Context, id uuid.UUID, month string) error {
	from, err := time.Parse("2006-01", month)
	if err != nil {
		return ErrInvalid
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var paidEver, paidThisMonth bool
		var startsOn time.Time
		err := tx.QueryRow(ctx, "SELECT i.starts_on, EXISTS (SELECT 1 FROM home_fixed_payments p WHERE p.item_id = i.id), EXISTS (SELECT 1 FROM home_fixed_payments p WHERE p.item_id = i.id AND p.month = $2::date) FROM home_fixed_items i WHERE i.id = $1", id, from).Scan(&startsOn, &paidEver, &paidThisMonth)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("read fixed item: %w", err)
		}
		endsOn := from.AddDate(0, -1, 0)
		if paidThisMonth {
			endsOn = from
		}
		if !paidEver || endsOn.Before(startsOn) {
			if _, err := tx.Exec(ctx, "DELETE FROM home_fixed_items WHERE id = $1", id); err != nil {
				return fmt.Errorf("delete fixed item: %w", err)
			}
			return nil
		}
		if _, err := tx.Exec(ctx, "UPDATE home_fixed_items SET ends_on = $2::date, updated_at = now() WHERE id = $1", id, endsOn); err != nil {
			return fmt.Errorf("archive fixed item: %w", err)
		}
		return nil
	})
}

func scanFixedPayment(row pgx.CollectableRow) (FixedPayment, error) {
	var payment FixedPayment
	err := row.Scan(&payment.ID, &payment.ItemID, &payment.Month, &payment.AmountMinor, &payment.PaidOn, &payment.PaidBy, &payment.Note, &payment.ProofType)
	return payment, err
}

// SaveFixedPayment ticks one item for one month, or changes an existing tick. A zero amount means the item's own amount.
// Returns: the stored payment; ErrNotFound when the item does not exist; ErrInvalid when paidBy is not a member
// Handles: two phones ticking the same month (UNIQUE item_id, month: the later write wins, there is one payment)
func (s *Store) SaveFixedPayment(ctx context.Context, itemID uuid.UUID, month string, payment FixedPayment) (FixedPayment, error) {
	monthDate, err := time.Parse("2006-01", month)
	if err != nil {
		return FixedPayment{}, ErrInvalid
	}
	var saved FixedPayment
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var itemAmount int64
		if err := tx.QueryRow(ctx, "SELECT amount_minor FROM home_fixed_items WHERE id = $1", itemID).Scan(&itemAmount); errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return fmt.Errorf("read fixed item: %w", err)
		}
		amount := payment.AmountMinor
		if amount == 0 {
			amount = itemAmount
		}
		rows, err := tx.Query(ctx, "WITH upsert AS (INSERT INTO home_fixed_payments (id, item_id, month, amount_minor, paid_on, paid_by, note) VALUES ($1, $2, $3::date, $4, $5::date, $6, $7) ON CONFLICT (item_id, month) DO UPDATE SET amount_minor = EXCLUDED.amount_minor, paid_on = EXCLUDED.paid_on, paid_by = EXCLUDED.paid_by, note = EXCLUDED.note, updated_at = now() RETURNING id, item_id, month, amount_minor, paid_on, paid_by, note) SELECT p.id, p.item_id, to_char(p.month, 'YYYY-MM'), p.amount_minor, to_char(p.paid_on, 'YYYY-MM-DD'), p.paid_by, p.note, coalesce(pr.media_type, '') FROM upsert p LEFT JOIN home_fixed_proofs pr ON pr.payment_id = p.id", uuid.New(), itemID, monthDate, amount, payment.PaidOn, payment.PaidBy, payment.Note)
		if err != nil {
			return fmt.Errorf("save fixed payment: %w", err)
		}
		saved, err = pgx.CollectOneRow(rows, scanFixedPayment)
		if isCode(err, "23503") {
			return ErrInvalid
		}
		if err != nil {
			return fmt.Errorf("save fixed payment: %w", err)
		}
		return nil
	})
	if err != nil {
		return FixedPayment{}, err
	}
	return saved, nil
}

// RemoveFixedPayment unticks one month; the proof goes with it.
// Returns: ErrNotFound when that month was not ticked
func (s *Store) RemoveFixedPayment(ctx context.Context, itemID uuid.UUID, month string) error {
	monthDate, err := time.Parse("2006-01", month)
	if err != nil {
		return ErrInvalid
	}
	tag, err := s.pool.Exec(ctx, "DELETE FROM home_fixed_payments WHERE item_id = $1 AND month = $2::date", itemID, monthDate)
	if err != nil {
		return fmt.Errorf("remove fixed payment: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SaveFixedProof attaches a bill or receipt to one month's payment, replacing any earlier one.
// Returns: ErrNotFound when that month is not ticked
func (s *Store) SaveFixedProof(ctx context.Context, itemID uuid.UUID, month string, proof FixedProof) error {
	monthDate, err := time.Parse("2006-01", month)
	if err != nil {
		return ErrInvalid
	}
	tag, err := s.pool.Exec(ctx, "INSERT INTO home_fixed_proofs (payment_id, media_type, bytes, size) SELECT p.id, $3, $4, $5 FROM home_fixed_payments p WHERE p.item_id = $1 AND p.month = $2::date ON CONFLICT (payment_id) DO UPDATE SET media_type = EXCLUDED.media_type, bytes = EXCLUDED.bytes, size = EXCLUDED.size, created_at = now()", itemID, monthDate, proof.MediaType, proof.Bytes, len(proof.Bytes))
	if err != nil {
		return fmt.Errorf("save fixed proof: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// FixedProof reads the attachment on one month's payment.
// Returns: ErrNotFound when there is none
func (s *Store) FixedProof(ctx context.Context, itemID uuid.UUID, month string) (FixedProof, error) {
	monthDate, err := time.Parse("2006-01", month)
	if err != nil {
		return FixedProof{}, ErrInvalid
	}
	var proof FixedProof
	err = s.pool.QueryRow(ctx, "SELECT pr.media_type, pr.bytes FROM home_fixed_proofs pr JOIN home_fixed_payments p ON p.id = pr.payment_id WHERE p.item_id = $1 AND p.month = $2::date", itemID, monthDate).Scan(&proof.MediaType, &proof.Bytes)
	if errors.Is(err, pgx.ErrNoRows) {
		return FixedProof{}, ErrNotFound
	}
	if err != nil {
		return FixedProof{}, fmt.Errorf("read fixed proof: %w", err)
	}
	return proof, nil
}

// RemoveFixedProof takes the attachment off one month's payment; the tick stays.
// Returns: ErrNotFound when there was none
func (s *Store) RemoveFixedProof(ctx context.Context, itemID uuid.UUID, month string) error {
	monthDate, err := time.Parse("2006-01", month)
	if err != nil {
		return ErrInvalid
	}
	tag, err := s.pool.Exec(ctx, "DELETE FROM home_fixed_proofs pr USING home_fixed_payments p WHERE p.id = pr.payment_id AND p.item_id = $1 AND p.month = $2::date", itemID, monthDate)
	if err != nil {
		return fmt.Errorf("remove fixed proof: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
