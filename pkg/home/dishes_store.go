package home

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// MaxDishesPerSearch caps one library search.
const MaxDishesPerSearch = 50

// ErrSlotFull says a day's slot already holds MaxMealsPerDay dishes.
var ErrSlotFull = errors.New("home: slot full")

// Dish is one entry in the household's dish library: a name with the numbers and ingredients it had last time.
type Dish struct {
	ID          uuid.UUID    `json:"id"`
	Name        string       `json:"name"`
	Kcal        int          `json:"kcal"`
	ProteinG    int          `json:"proteinG"`
	CarbsG      int          `json:"carbsG"`
	FatG        int          `json:"fatG"`
	Serves      int          `json:"serves"`
	Ingredients []Ingredient `json:"ingredients"`
	TimesUsed   int          `json:"timesUsed"`
	LastUsedAt  time.Time    `json:"lastUsedAt"`
}

// dishKey folds a dish name so "Curd Rice", "curd  rice" and " CURD RICE " share one library entry.
func dishKey(name string) string {
	return strings.ToLower(strings.Join(strings.Fields(name), " "))
}

func scanDish(row pgx.CollectableRow) (Dish, error) {
	var dish Dish
	var ingredients []byte
	if err := row.Scan(&dish.ID, &dish.Name, &dish.Kcal, &dish.ProteinG, &dish.CarbsG, &dish.FatG, &dish.Serves, &ingredients, &dish.TimesUsed, &dish.LastUsedAt); err != nil {
		return Dish{}, err
	}
	dish.Ingredients = []Ingredient{}
	if err := json.Unmarshal(ingredients, &dish.Ingredients); err != nil {
		return Dish{}, fmt.Errorf("decode ingredients: %w", err)
	}
	return dish, nil
}

// SearchDishes finds library dishes for a typed prefix: names starting with it first, then names containing it,
// most recently used first. An empty query lists the most recent dishes.
// Args: ctx, query (any text; LIKE wildcards are escaped), limit (1..MaxDishesPerSearch)
func (s *Store) SearchDishes(ctx context.Context, query string, limit int) ([]Dish, error) {
	key := dishKey(query)
	escaped := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(key)
	rows, err := s.pool.Query(ctx, "SELECT id, name, kcal, protein_g, carbs_g, fat_g, serves, ingredients, times_used, last_used_at FROM home_dishes WHERE $1 = '' OR name_key LIKE '%' || $1 || '%' ORDER BY CASE WHEN $1 <> '' AND name_key LIKE $1 || '%' THEN 0 ELSE 1 END, last_used_at DESC, times_used DESC, name LIMIT $2", escaped, limit)
	if err != nil {
		return nil, fmt.Errorf("search dishes: %w", err)
	}
	dishes, err := pgx.CollectRows(rows, scanDish)
	if err != nil {
		return nil, fmt.Errorf("scan dishes: %w", err)
	}
	return dishes, nil
}

// learnDishes upserts every meal's dish into the library inside a transaction, numbers overwriting the old entry
// and the usage count going up by one. The last of two same-named meals in the batch wins.
func learnDishes(ctx context.Context, tx pgx.Tx, meals []Meal, actor uuid.UUID) error {
	byKey := map[string]Meal{}
	keys := make([]string, 0, len(meals))
	for _, meal := range meals {
		key := dishKey(meal.Name)
		if _, seen := byKey[key]; !seen {
			keys = append(keys, key)
		}
		byKey[key] = meal
	}
	batch := &pgx.Batch{}
	for _, key := range keys {
		meal := byKey[key]
		ingredients, err := encodeIngredients(meal.Ingredients)
		if err != nil {
			return err
		}
		batch.Queue("INSERT INTO home_dishes (id, name, name_key, kcal, protein_g, carbs_g, fat_g, serves, ingredients, times_used, created_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, 1, $10) ON CONFLICT (name_key) DO UPDATE SET name = EXCLUDED.name, kcal = EXCLUDED.kcal, protein_g = EXCLUDED.protein_g, carbs_g = EXCLUDED.carbs_g, fat_g = EXCLUDED.fat_g, serves = EXCLUDED.serves, ingredients = EXCLUDED.ingredients, times_used = home_dishes.times_used + 1, last_used_at = now(), updated_at = now()", uuid.New(), strings.Join(strings.Fields(meal.Name), " "), key, meal.Kcal, meal.ProteinG, meal.CarbsG, meal.FatG, meal.Serves, ingredients, actor)
	}
	if err := tx.SendBatch(ctx, batch).Close(); err != nil {
		return fmt.Errorf("learn dishes: %w", err)
	}
	return nil
}

// AddMeal puts one dish on one day and records it in the library, in one transaction.
// A name the library has not seen is added with these numbers. A known name counts one more use; its stored
// numbers change only when overwrite is set.
// Each eater gets a tick at their portion in the same transaction, so a meal never lands half-logged.
// Returns: the stored meal with its dish id; ErrSlotFull when the slot already holds MaxMealsPerDay dishes;
// ErrInvalid when an eater is not a member of this home
// Handles: two adds at once (the same lock as an import), so the slot cap and sort order hold
func (s *Store) AddMeal(ctx context.Context, meal Meal, actor uuid.UUID, overwrite bool, eaters []MealTick) (Meal, error) {
	ingredients, err := encodeIngredients(meal.Ingredients)
	if err != nil {
		return Meal{}, err
	}
	id := uuid.New()
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(7340103)"); err != nil {
			return fmt.Errorf("lock meals: %w", err)
		}
		var count int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM home_meals WHERE day = $1::date AND slot = $2", meal.Day, meal.Slot).Scan(&count); err != nil {
			return fmt.Errorf("count slot: %w", err)
		}
		if count >= MaxMealsPerDay {
			return ErrSlotFull
		}
		var dishID uuid.UUID
		if err := tx.QueryRow(ctx, "INSERT INTO home_dishes (id, name, name_key, kcal, protein_g, carbs_g, fat_g, serves, ingredients, times_used, created_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, 1, $10) ON CONFLICT (name_key) DO UPDATE SET name = CASE WHEN $11 THEN EXCLUDED.name ELSE home_dishes.name END, kcal = CASE WHEN $11 THEN EXCLUDED.kcal ELSE home_dishes.kcal END, protein_g = CASE WHEN $11 THEN EXCLUDED.protein_g ELSE home_dishes.protein_g END, carbs_g = CASE WHEN $11 THEN EXCLUDED.carbs_g ELSE home_dishes.carbs_g END, fat_g = CASE WHEN $11 THEN EXCLUDED.fat_g ELSE home_dishes.fat_g END, serves = CASE WHEN $11 THEN EXCLUDED.serves ELSE home_dishes.serves END, ingredients = CASE WHEN $11 THEN EXCLUDED.ingredients ELSE home_dishes.ingredients END, times_used = home_dishes.times_used + 1, last_used_at = now(), updated_at = CASE WHEN $11 THEN now() ELSE home_dishes.updated_at END RETURNING id", uuid.New(), strings.Join(strings.Fields(meal.Name), " "), dishKey(meal.Name), meal.Kcal, meal.ProteinG, meal.CarbsG, meal.FatG, meal.Serves, ingredients, actor, overwrite).Scan(&dishID); err != nil {
			return fmt.Errorf("learn dish: %w", err)
		}
		if _, err := tx.Exec(ctx, "INSERT INTO home_meals (id, day, slot, name, kcal, protein_g, carbs_g, fat_g, serves, ingredients, sort_order, created_by, dish_id) VALUES ($1, $2::date, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, (SELECT coalesce(max(sort_order) + 1, 0) FROM home_meals WHERE day = $2::date AND slot = $3), $11, $12)", id, meal.Day, meal.Slot, meal.Name, meal.Kcal, meal.ProteinG, meal.CarbsG, meal.FatG, meal.Serves, ingredients, actor, dishID); err != nil {
			return fmt.Errorf("add meal: %w", err)
		}
		for _, eater := range eaters {
			_, err := tx.Exec(ctx, "INSERT INTO home_meal_ticks (meal_id, user_id, portion) VALUES ($1, $2, $3) ON CONFLICT (meal_id, user_id) DO UPDATE SET portion = EXCLUDED.portion", id, eater.UserID, eater.Portion)
			if isCode(err, "23503") {
				return fmt.Errorf("%w: that person is not in this home", ErrInvalid)
			}
			if err != nil {
				return fmt.Errorf("tick eater: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return Meal{}, err
	}
	return s.MealByID(ctx, id)
}
