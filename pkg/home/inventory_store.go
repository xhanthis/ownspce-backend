package home

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// MaxInventoryItems caps one stock read.
const MaxInventoryItems = 500

// MaxInventoryMoves caps the history returned with the stock.
const MaxInventoryMoves = 100

// Inventory units: everything in stock is kept in grams, millilitres or pieces.
const (
	UnitGram  = "g"
	UnitMilli = "ml"
	UnitPiece = "pcs"
)

// ErrUnitMismatch says an item is kept in one unit and the change came in another.
var ErrUnitMismatch = errors.New("home: unit mismatch")

var inventoryUnits = set(UnitGram, UnitMilli, UnitPiece)

// Quantity is an amount in one of the three base units.
type Quantity struct {
	Amount float64 `json:"amount"`
	Unit   string  `json:"unit"`
}

// InventoryItem is one thing kept at home and how much of it is left.
type InventoryItem struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Unit      string    `json:"unit"`
	Qty       float64   `json:"qty"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// InventoryMove is one change to one item: what moved, why, and the meal it came from when there was one.
type InventoryMove struct {
	ID              uuid.UUID  `json:"id"`
	ItemID          uuid.UUID  `json:"itemId"`
	ItemName        string     `json:"itemName"`
	Unit            string     `json:"unit"`
	Delta           float64    `json:"delta"`
	Reason          string     `json:"reason"`
	MealID          *uuid.UUID `json:"mealId"`
	MealName        string     `json:"mealName"`
	IngredientIndex *int       `json:"ingredientIndex"`
	Note            string     `json:"note"`
	CreatedAt       time.Time  `json:"createdAt"`
}

// CookResult says what a meal tick took out of stock and which recipe lines it could not count.
type CookResult struct {
	Deducted []CookedLine `json:"deducted"`
	Skipped  []string     `json:"skipped"`
}

// CookedLine is one ingredient taken from stock, in the item's unit.
type CookedLine struct {
	Name   string  `json:"name"`
	Amount float64 `json:"amount"`
	Unit   string  `json:"unit"`
}

var (
	quantityRule  = regexp.MustCompile(`^(\d+\s+\d+/\d+|\d+/\d+|\d+(?:[.,]\d+)?|[½¼¾])\s*([a-zA-Z]*)\.?$`)
	parenthetical = regexp.MustCompile(`\([^)]*\)`)
	unitScale     = map[string]Quantity{
		"g": {1, UnitGram}, "gm": {1, UnitGram}, "gms": {1, UnitGram}, "gram": {1, UnitGram}, "grams": {1, UnitGram}, "gr": {1, UnitGram},
		"kg": {1000, UnitGram}, "kgs": {1000, UnitGram}, "kilo": {1000, UnitGram}, "kilos": {1000, UnitGram}, "kilogram": {1000, UnitGram}, "kilograms": {1000, UnitGram},
		"mg": {0.001, UnitGram},
		"ml": {1, UnitMilli}, "mls": {1, UnitMilli}, "millilitre": {1, UnitMilli}, "millilitres": {1, UnitMilli}, "milliliter": {1, UnitMilli}, "milliliters": {1, UnitMilli},
		"l": {1000, UnitMilli}, "ltr": {1000, UnitMilli}, "ltrs": {1000, UnitMilli}, "lt": {1000, UnitMilli}, "litre": {1000, UnitMilli}, "litres": {1000, UnitMilli}, "liter": {1000, UnitMilli}, "liters": {1000, UnitMilli},
		"": {1, UnitPiece}, "pc": {1, UnitPiece}, "pcs": {1, UnitPiece}, "piece": {1, UnitPiece}, "pieces": {1, UnitPiece}, "no": {1, UnitPiece}, "nos": {1, UnitPiece}, "num": {1, UnitPiece},
		"unit": {1, UnitPiece}, "units": {1, UnitPiece}, "pkt": {1, UnitPiece}, "pkts": {1, UnitPiece}, "packet": {1, UnitPiece}, "packets": {1, UnitPiece}, "pack": {1, UnitPiece}, "packs": {1, UnitPiece},
		"bunch": {1, UnitPiece}, "bunches": {1, UnitPiece}, "dozen": {12, UnitPiece}, "doz": {12, UnitPiece},
	}
)

// ParseQuantity reads a recipe or shopping amount into a base unit: "200 g", "1 kg", "1.5kg", "1/2 kg", "500 ml",
// "1 L", "2", "2 pcs", "1 dozen". Text after a bracket is ignored, so "200 g (2 medium)" reads as 200 g.
// Returns: the quantity and true, or false for anything it cannot count ("1 tsp", "a pinch", "to taste")
func ParseQuantity(text string) (Quantity, bool) {
	cleaned := strings.ToLower(strings.TrimSpace(parenthetical.ReplaceAllString(text, "")))
	match := quantityRule.FindStringSubmatch(cleaned)
	if match == nil {
		return Quantity{}, false
	}
	amount, ok := parseAmount(match[1])
	scale, known := unitScale[match[2]]
	if !ok || !known || amount <= 0 {
		return Quantity{}, false
	}
	return Quantity{Amount: math.Round(amount*scale.Amount*100) / 100, Unit: scale.Unit}, true
}

func parseAmount(text string) (float64, bool) {
	switch text {
	case "½":
		return 0.5, true
	case "¼":
		return 0.25, true
	case "¾":
		return 0.75, true
	}
	whole := 0.0
	fraction := text
	if fields := strings.Fields(text); len(fields) == 2 {
		parsed, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			return 0, false
		}
		whole, fraction = parsed, fields[1]
	}
	if numerator, denominator, found := strings.Cut(fraction, "/"); found {
		top, errTop := strconv.ParseFloat(numerator, 64)
		bottom, errBottom := strconv.ParseFloat(denominator, 64)
		if errTop != nil || errBottom != nil || bottom == 0 {
			return 0, false
		}
		return whole + top/bottom, true
	}
	parsed, err := strconv.ParseFloat(strings.ReplaceAll(fraction, ",", "."), 64)
	if err != nil {
		return 0, false
	}
	return whole + parsed, true
}

// itemKey folds an item name so "Tomatoes", "tomato" and " TOMATO " are one stock row: lower case, one space between
// words, a trailing full stop dropped, and the last word made singular by the common English rules.
func itemKey(name string) string {
	words := strings.Fields(strings.ToLower(strings.TrimRight(strings.TrimSpace(name), ".")))
	if len(words) == 0 {
		return ""
	}
	last := words[len(words)-1]
	switch {
	case len(last) > 4 && strings.HasSuffix(last, "ies"):
		last = strings.TrimSuffix(last, "ies") + "y"
	case len(last) > 4 && (strings.HasSuffix(last, "oes") || strings.HasSuffix(last, "ches") || strings.HasSuffix(last, "shes") || strings.HasSuffix(last, "sses") || strings.HasSuffix(last, "xes")):
		last = strings.TrimSuffix(last, "es")
	case len(last) > 3 && strings.HasSuffix(last, "s") && !strings.HasSuffix(last, "ss"):
		last = strings.TrimSuffix(last, "s")
	}
	words[len(words)-1] = last
	return strings.Join(words, " ")
}

func displayName(name string) string {
	return strings.Join(strings.Fields(name), " ")
}

func decodeIngredients(raw []byte) ([]Ingredient, error) {
	ingredients := []Ingredient{}
	if err := json.Unmarshal(raw, &ingredients); err != nil {
		return nil, fmt.Errorf("decode ingredients: %w", err)
	}
	return ingredients, nil
}

func scanInventoryItem(row pgx.CollectableRow) (InventoryItem, error) {
	var item InventoryItem
	err := row.Scan(&item.ID, &item.Name, &item.Unit, &item.Qty, &item.UpdatedAt)
	return item, err
}

func scanInventoryMove(row pgx.CollectableRow) (InventoryMove, error) {
	var move InventoryMove
	var mealName *string
	if err := row.Scan(&move.ID, &move.ItemID, &move.ItemName, &move.Unit, &move.Delta, &move.Reason, &move.MealID, &mealName, &move.IngredientIndex, &move.Note, &move.CreatedAt); err != nil {
		return InventoryMove{}, err
	}
	if mealName != nil {
		move.MealName = *mealName
	}
	return move, nil
}

// Inventory lists everything in stock by name and the most recent moves with the meal each came from.
// Returns: up to MaxInventoryItems items and MaxInventoryMoves moves
func (s *Store) Inventory(ctx context.Context) ([]InventoryItem, []InventoryMove, error) {
	rows, err := s.pool.Query(ctx, "SELECT id, name, unit, qty::float8, updated_at FROM home_inventory_items ORDER BY name, id LIMIT $1", MaxInventoryItems)
	if err != nil {
		return nil, nil, fmt.Errorf("list inventory: %w", err)
	}
	items, err := pgx.CollectRows(rows, scanInventoryItem)
	if err != nil {
		return nil, nil, fmt.Errorf("scan inventory: %w", err)
	}
	rows, err = s.pool.Query(ctx, "SELECT v.id, v.item_id, i.name, i.unit, v.delta::float8, v.reason, v.meal_id, m.name, v.ingredient_index, v.note, v.created_at FROM home_inventory_moves v JOIN home_inventory_items i ON i.id = v.item_id LEFT JOIN home_meals m ON m.id = v.meal_id ORDER BY v.created_at DESC, v.id LIMIT $1", MaxInventoryMoves)
	if err != nil {
		return nil, nil, fmt.Errorf("list inventory moves: %w", err)
	}
	moves, err := pgx.CollectRows(rows, scanInventoryMove)
	if err != nil {
		return nil, nil, fmt.Errorf("scan inventory moves: %w", err)
	}
	return items, moves, nil
}

// InventoryItemByID reads one stock row.
// Returns: ErrNotFound when there is no such item
func (s *Store) InventoryItemByID(ctx context.Context, id uuid.UUID) (InventoryItem, error) {
	rows, err := s.pool.Query(ctx, "SELECT id, name, unit, qty::float8, updated_at FROM home_inventory_items WHERE id = $1 LIMIT 1", id)
	if err != nil {
		return InventoryItem{}, fmt.Errorf("read inventory item: %w", err)
	}
	item, err := pgx.CollectOneRow(rows, scanInventoryItem)
	if errors.Is(err, pgx.ErrNoRows) {
		return InventoryItem{}, ErrNotFound
	}
	if err != nil {
		return InventoryItem{}, fmt.Errorf("scan inventory item: %w", err)
	}
	return item, nil
}

// AddStock puts a bought amount into stock, creating the item on first sight, and records the move, in one
// transaction. With a meal and ingredient index the move stands for one recipe line ticked as bought: a second tick
// of the same line changes nothing and returns the item as it is.
// Args: ctx, name (any spelling; folded by itemKey), quantity, reason (bought or scanned), mealID and ingredientIndex
// (both or neither), actor
// Returns: the item after the change; ErrUnitMismatch when the item is kept in another unit
func (s *Store) AddStock(ctx context.Context, name string, quantity Quantity, reason string, mealID *uuid.UUID, ingredientIndex *int, actor uuid.UUID) (InventoryItem, error) {
	var item InventoryItem
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(7340105)"); err != nil {
			return fmt.Errorf("lock inventory: %w", err)
		}
		if mealID != nil {
			var already bool
			if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM home_inventory_moves WHERE meal_id = $1 AND ingredient_index = $2 AND reason = 'bought')", *mealID, *ingredientIndex).Scan(&already); err != nil {
				return fmt.Errorf("check bought line: %w", err)
			}
			if already {
				return ErrConflict
			}
		}
		rows, err := tx.Query(ctx, "INSERT INTO home_inventory_items (id, name, name_key, unit, qty) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (name_key) DO UPDATE SET qty = home_inventory_items.qty + EXCLUDED.qty, updated_at = now() WHERE home_inventory_items.unit = EXCLUDED.unit RETURNING id, name, unit, qty::float8, updated_at", uuid.New(), displayName(name), itemKey(name), quantity.Unit, quantity.Amount)
		if err != nil {
			return fmt.Errorf("add stock: %w", err)
		}
		item, err = pgx.CollectOneRow(rows, scanInventoryItem)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrUnitMismatch
		}
		if err != nil {
			return fmt.Errorf("scan stock: %w", err)
		}
		if _, err := tx.Exec(ctx, "INSERT INTO home_inventory_moves (id, item_id, delta, reason, meal_id, ingredient_index, created_by) VALUES ($1, $2, $3, $4, $5, $6, $7)", uuid.New(), item.ID, quantity.Amount, reason, mealID, ingredientIndex, actor); err != nil {
			return fmt.Errorf("record stock move: %w", err)
		}
		return nil
	})
	if errors.Is(err, ErrConflict) {
		return s.itemByKey(ctx, itemKey(name))
	}
	if err != nil {
		return InventoryItem{}, err
	}
	return item, nil
}

func (s *Store) itemByKey(ctx context.Context, key string) (InventoryItem, error) {
	rows, err := s.pool.Query(ctx, "SELECT id, name, unit, qty::float8, updated_at FROM home_inventory_items WHERE name_key = $1 LIMIT 1", key)
	if err != nil {
		return InventoryItem{}, fmt.Errorf("read inventory item: %w", err)
	}
	item, err := pgx.CollectOneRow(rows, scanInventoryItem)
	if errors.Is(err, pgx.ErrNoRows) {
		return InventoryItem{}, ErrNotFound
	}
	if err != nil {
		return InventoryItem{}, fmt.Errorf("scan inventory item: %w", err)
	}
	return item, nil
}

// UnbuyLine undoes one recipe line ticked as bought: the move goes and its amount leaves stock again, floored at zero.
// Returns: the item after the change; ErrNotFound when that line was never ticked
func (s *Store) UnbuyLine(ctx context.Context, mealID uuid.UUID, ingredientIndex int) (InventoryItem, error) {
	var itemID uuid.UUID
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(7340105)"); err != nil {
			return fmt.Errorf("lock inventory: %w", err)
		}
		var delta float64
		err := tx.QueryRow(ctx, "DELETE FROM home_inventory_moves WHERE meal_id = $1 AND ingredient_index = $2 AND reason = 'bought' RETURNING item_id, delta::float8", mealID, ingredientIndex).Scan(&itemID, &delta)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("remove bought line: %w", err)
		}
		if _, err := tx.Exec(ctx, "UPDATE home_inventory_items SET qty = greatest(0, qty - $2), updated_at = now() WHERE id = $1", itemID, delta); err != nil {
			return fmt.Errorf("take back stock: %w", err)
		}
		return nil
	})
	if err != nil {
		return InventoryItem{}, err
	}
	return s.InventoryItemByID(ctx, itemID)
}

// InventoryPatch is what a hand correction may change. Nil leaves a field alone.
type InventoryPatch struct {
	Name *string
	Unit *string
	Qty  *float64
}

// SetStock corrects one item by hand and records the difference as an adjusted move.
// Returns: the item after the change; ErrNotFound for an unknown id; ErrConflict when the new name is another item's
func (s *Store) SetStock(ctx context.Context, id uuid.UUID, patch InventoryPatch, actor uuid.UUID) (InventoryItem, error) {
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(7340105)"); err != nil {
			return fmt.Errorf("lock inventory: %w", err)
		}
		var before float64
		err := tx.QueryRow(ctx, "SELECT qty::float8 FROM home_inventory_items WHERE id = $1 FOR UPDATE", id).Scan(&before)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("read stock: %w", err)
		}
		var name, key *string
		if patch.Name != nil {
			shown, folded := displayName(*patch.Name), itemKey(*patch.Name)
			name, key = &shown, &folded
		}
		if _, err := tx.Exec(ctx, "UPDATE home_inventory_items SET name = coalesce($2, name), name_key = coalesce($3, name_key), unit = coalesce($4, unit), qty = coalesce($5, qty), updated_at = now() WHERE id = $1", id, name, key, patch.Unit, patch.Qty); err != nil {
			if isCode(err, "23505") {
				return ErrConflict
			}
			return fmt.Errorf("set stock: %w", err)
		}
		if patch.Qty == nil || *patch.Qty == before {
			return nil
		}
		if _, err := tx.Exec(ctx, "INSERT INTO home_inventory_moves (id, item_id, delta, reason, created_by) VALUES ($1, $2, $3, 'adjusted', $4)", uuid.New(), id, *patch.Qty-before, actor); err != nil {
			return fmt.Errorf("record adjustment: %w", err)
		}
		return nil
	})
	if err != nil {
		return InventoryItem{}, err
	}
	return s.InventoryItemByID(ctx, id)
}

// RemoveInventoryItem drops one item and every move that touched it.
// Returns: ErrNotFound when there is no such item
func (s *Store) RemoveInventoryItem(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, "DELETE FROM home_inventory_items WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("remove inventory item: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// CookMeal takes a ticked meal's ingredients out of stock, once per meal however many members tick it.
// A line is skipped, and named in the result, when its amount cannot be read, the item is not in stock, or the item
// is kept in another unit. Stock never goes below zero: a short item gives what it has.
// Returns: what was deducted and what was skipped; ErrNotFound when there is no such meal
// Handles: two ticks at once (one inventory lock, and a cooked move already present means nothing more is taken)
func (s *Store) CookMeal(ctx context.Context, mealID, actor uuid.UUID) (CookResult, error) {
	result := CookResult{Deducted: []CookedLine{}, Skipped: []string{}}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(7340105)"); err != nil {
			return fmt.Errorf("lock inventory: %w", err)
		}
		var cooked bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM home_inventory_moves WHERE meal_id = $1 AND reason = 'cooked')", mealID).Scan(&cooked); err != nil {
			return fmt.Errorf("check cooked: %w", err)
		}
		if cooked {
			return nil
		}
		var raw []byte
		err := tx.QueryRow(ctx, "SELECT ingredients FROM home_meals WHERE id = $1", mealID).Scan(&raw)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("read meal ingredients: %w", err)
		}
		ingredients, err := decodeIngredients(raw)
		if err != nil {
			return err
		}
		keys := make([]string, 0, len(ingredients))
		for _, ingredient := range ingredients {
			keys = append(keys, itemKey(ingredient.Name))
		}
		rows, err := tx.Query(ctx, "SELECT id, name, name_key, unit, qty::float8 FROM home_inventory_items WHERE name_key = ANY($1::text[]) ORDER BY id FOR UPDATE", keys)
		if err != nil {
			return fmt.Errorf("find stock: %w", err)
		}
		type stockRow struct {
			item InventoryItem
			key  string
		}
		stock, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (stockRow, error) {
			var entry stockRow
			err := row.Scan(&entry.item.ID, &entry.item.Name, &entry.key, &entry.item.Unit, &entry.item.Qty)
			return entry, err
		})
		if err != nil {
			return fmt.Errorf("scan stock: %w", err)
		}
		onHand := make(map[string]*InventoryItem, len(stock))
		for index := range stock {
			onHand[stock[index].key] = &stock[index].item
		}
		batch := &pgx.Batch{}
		for index, ingredient := range ingredients {
			quantity, ok := ParseQuantity(ingredient.Qty)
			item := onHand[keys[index]]
			if !ok || item == nil || item.Unit != quantity.Unit || item.Qty <= 0 {
				result.Skipped = append(result.Skipped, ingredient.Name)
				continue
			}
			taken := math.Min(item.Qty, quantity.Amount)
			item.Qty -= taken
			batch.Queue("UPDATE home_inventory_items SET qty = qty - $2, updated_at = now() WHERE id = $1", item.ID, taken)
			batch.Queue("INSERT INTO home_inventory_moves (id, item_id, delta, reason, meal_id, note, created_by) VALUES ($1, $2, $3, 'cooked', $4, $5, $6)", uuid.New(), item.ID, -taken, mealID, ingredient.Name, actor)
			result.Deducted = append(result.Deducted, CookedLine{Name: item.Name, Amount: taken, Unit: item.Unit})
		}
		if batch.Len() == 0 {
			return nil
		}
		if err := tx.SendBatch(ctx, batch).Close(); err != nil {
			return fmt.Errorf("take stock: %w", err)
		}
		return nil
	})
	if err != nil {
		return CookResult{}, err
	}
	return result, nil
}

// UncookMeal puts a meal's ingredients back when the last tick on it is cleared. With ticks still standing it does
// nothing. What comes back is what the cooked moves recorded, not what the recipe says today.
func (s *Store) UncookMeal(ctx context.Context, mealID uuid.UUID) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(7340105)"); err != nil {
			return fmt.Errorf("lock inventory: %w", err)
		}
		var ticks int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM home_meal_ticks WHERE meal_id = $1", mealID).Scan(&ticks); err != nil {
			return fmt.Errorf("count ticks: %w", err)
		}
		if ticks > 0 {
			return nil
		}
		if _, err := tx.Exec(ctx, "UPDATE home_inventory_items i SET qty = i.qty - v.taken, updated_at = now() FROM (SELECT item_id, sum(delta) AS taken FROM home_inventory_moves WHERE meal_id = $1 AND reason = 'cooked' GROUP BY item_id) v WHERE i.id = v.item_id", mealID); err != nil {
			return fmt.Errorf("return stock: %w", err)
		}
		if _, err := tx.Exec(ctx, "DELETE FROM home_inventory_moves WHERE meal_id = $1 AND reason = 'cooked'", mealID); err != nil {
			return fmt.Errorf("clear cooked moves: %w", err)
		}
		return nil
	})
}
