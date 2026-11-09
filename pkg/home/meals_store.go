package home

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// MaxMealsPerRead caps one meal plan read.
const MaxMealsPerRead = 1000

// MaxMealImportDays caps the days one pasted menu may cover.
const MaxMealImportDays = 60

// MaxMealsPerDay caps the meals one day may hold.
const MaxMealsPerDay = 10

type Ingredient struct {
	Name string `json:"name"`
	Qty  string `json:"qty"`
	Link string `json:"link"`
}

// Meal is one planned dish on one day. TickedBy lists the members who marked it as eaten.
type Meal struct {
	ID          uuid.UUID    `json:"id"`
	DishID      *uuid.UUID   `json:"dishId"`
	Day         string       `json:"day"`
	Slot        string       `json:"slot"`
	Name        string       `json:"name"`
	Kcal        int          `json:"kcal"`
	ProteinG    int          `json:"proteinG"`
	CarbsG      int          `json:"carbsG"`
	FatG        int          `json:"fatG"`
	Serves      int          `json:"serves"`
	Ingredients []Ingredient `json:"ingredients"`
	SortOrder   int          `json:"sortOrder"`
	OrderedIn   bool         `json:"orderedIn"`
	TickedBy    []uuid.UUID  `json:"tickedBy"`
	Ticks       []MealTick   `json:"ticks"`
	UpdatedAt   time.Time    `json:"updatedAt"`
}

// MealTick is one member's plate of a meal: who, and how many portions of the meal's per-plate numbers.
type MealTick struct {
	UserID  uuid.UUID `json:"userId"`
	Portion float64   `json:"portion"`
}

// mealPortions are the plate sizes a tick may carry; the app offers the same five.
var mealPortions = map[float64]bool{0.5: true, 1: true, 1.5: true, 2: true, 3: true}

// validPortion reports whether a portion is an allowed plate size. Zero means "not given" and reads as one plate.
func validPortion(portion float64) bool { return portion == 0 || mealPortions[portion] }

// MealImportResult counts what a pasted menu holds and how many of its days replaced an existing plan.
type MealImportResult struct {
	Days     int `json:"days"`
	Meals    int `json:"meals"`
	Replaced int `json:"replaced"`
}

func scanMeal(row pgx.CollectableRow) (Meal, error) {
	var meal Meal
	var ingredients []byte
	var ticks []byte
	if err := row.Scan(&meal.ID, &meal.DishID, &meal.Day, &meal.Slot, &meal.Name, &meal.Kcal, &meal.ProteinG, &meal.CarbsG, &meal.FatG, &meal.Serves, &ingredients, &meal.SortOrder, &meal.OrderedIn, &ticks, &meal.UpdatedAt); err != nil {
		return Meal{}, err
	}
	meal.Ingredients = []Ingredient{}
	if err := json.Unmarshal(ingredients, &meal.Ingredients); err != nil {
		return Meal{}, fmt.Errorf("decode ingredients: %w", err)
	}
	meal.Ticks = []MealTick{}
	if err := json.Unmarshal(ticks, &meal.Ticks); err != nil {
		return Meal{}, fmt.Errorf("decode ticks: %w", err)
	}
	meal.TickedBy = make([]uuid.UUID, 0, len(meal.Ticks))
	for _, tick := range meal.Ticks {
		meal.TickedBy = append(meal.TickedBy, tick.UserID)
	}
	return meal, nil
}

func encodeIngredients(ingredients []Ingredient) (string, error) {
	if ingredients == nil {
		ingredients = []Ingredient{}
	}
	raw, err := json.Marshal(ingredients)
	if err != nil {
		return "", fmt.Errorf("encode ingredients: %w", err)
	}
	return string(raw), nil
}

// Meals lists the plan between two days, newest day first and breakfast before dinner, with who ticked each meal.
// Args: ctx, from, to (yyyy-mm-dd, validated by the caller)
// Returns: up to MaxMealsPerRead meals, and whether more existed beyond the cap
func (s *Store) Meals(ctx context.Context, from, to string) ([]Meal, bool, error) {
	rows, err := s.pool.Query(ctx, "SELECT m.id, m.dish_id, to_char(m.day, 'YYYY-MM-DD'), m.slot, m.name, m.kcal, m.protein_g, m.carbs_g, m.fat_g, m.serves, m.ingredients, m.sort_order, m.ordered_in, coalesce(jsonb_agg(jsonb_build_object('userId', t.user_id, 'portion', t.portion::float8) ORDER BY t.ticked_at, t.user_id) FILTER (WHERE t.user_id IS NOT NULL), '[]'::jsonb), m.updated_at FROM home_meals m LEFT JOIN home_meal_ticks t ON t.meal_id = m.id WHERE m.day BETWEEN $1::date AND $2::date GROUP BY m.id ORDER BY m.day DESC, CASE m.slot WHEN 'breakfast' THEN 0 WHEN 'lunch' THEN 1 WHEN 'snack' THEN 2 ELSE 3 END, m.sort_order, m.id LIMIT $3", from, to, MaxMealsPerRead+1)
	if err != nil {
		return nil, false, fmt.Errorf("list meals: %w", err)
	}
	meals, err := pgx.CollectRows(rows, scanMeal)
	if err != nil {
		return nil, false, fmt.Errorf("scan meals: %w", err)
	}
	if len(meals) > MaxMealsPerRead {
		return meals[:MaxMealsPerRead], true, nil
	}
	return meals, false, nil
}

// MealByID reads one meal with its ticks.
// Returns: ErrNotFound when there is no such meal
func (s *Store) MealByID(ctx context.Context, id uuid.UUID) (Meal, error) {
	rows, err := s.pool.Query(ctx, "SELECT m.id, m.dish_id, to_char(m.day, 'YYYY-MM-DD'), m.slot, m.name, m.kcal, m.protein_g, m.carbs_g, m.fat_g, m.serves, m.ingredients, m.sort_order, m.ordered_in, coalesce(jsonb_agg(jsonb_build_object('userId', t.user_id, 'portion', t.portion::float8) ORDER BY t.ticked_at, t.user_id) FILTER (WHERE t.user_id IS NOT NULL), '[]'::jsonb), m.updated_at FROM home_meals m LEFT JOIN home_meal_ticks t ON t.meal_id = m.id WHERE m.id = $1 GROUP BY m.id LIMIT 1", id)
	if err != nil {
		return Meal{}, fmt.Errorf("read meal: %w", err)
	}
	meal, err := pgx.CollectOneRow(rows, scanMeal)
	if errors.Is(err, pgx.ErrNoRows) {
		return Meal{}, ErrNotFound
	}
	if err != nil {
		return Meal{}, fmt.Errorf("scan meal: %w", err)
	}
	return meal, nil
}

// ReplaceMeal rewrites the editable fields of one meal, keeping its ticks.
// Returns: the stored meal; ErrNotFound when there is no such meal
func (s *Store) ReplaceMeal(ctx context.Context, id uuid.UUID, meal Meal) (Meal, error) {
	ingredients, err := encodeIngredients(meal.Ingredients)
	if err != nil {
		return Meal{}, err
	}
	tag, err := s.pool.Exec(ctx, "UPDATE home_meals SET day = $2::date, slot = $3, name = $4, kcal = $5, protein_g = $6, carbs_g = $7, fat_g = $8, serves = $9, ingredients = $10::jsonb, ordered_in = $11, updated_at = now() WHERE id = $1", id, meal.Day, meal.Slot, meal.Name, meal.Kcal, meal.ProteinG, meal.CarbsG, meal.FatG, meal.Serves, ingredients, meal.OrderedIn)
	if err != nil {
		return Meal{}, fmt.Errorf("replace meal: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return Meal{}, ErrNotFound
	}
	return s.MealByID(ctx, id)
}

// RemoveMeal takes one meal, and its ticks, out of the plan.
// Returns: ErrNotFound when there is no such meal
func (s *Store) RemoveMeal(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, "DELETE FROM home_meals WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("remove meal: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// TickMeal records, or clears, that one member ate a meal at a portion. Ticking twice keeps one tick with the latest
// portion; clearing twice is fine. A portion of zero means one plate.
// Returns: ErrNotFound when there is no such meal; ErrInvalid when the member is not in this home
func (s *Store) TickMeal(ctx context.Context, id, userID uuid.UUID, portion float64, ate bool) error {
	if portion == 0 {
		portion = 1
	}
	var exists bool
	if err := s.pool.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM home_meals WHERE id = $1)", id).Scan(&exists); err != nil {
		return fmt.Errorf("check meal: %w", err)
	}
	if !exists {
		return ErrNotFound
	}
	var err error
	if ate {
		_, err = s.pool.Exec(ctx, "INSERT INTO home_meal_ticks (meal_id, user_id, portion) VALUES ($1, $2, $3) ON CONFLICT (meal_id, user_id) DO UPDATE SET portion = EXCLUDED.portion, ticked_at = now()", id, userID, portion)
	} else {
		_, err = s.pool.Exec(ctx, "DELETE FROM home_meal_ticks WHERE meal_id = $1 AND user_id = $2", id, userID)
	}
	if isCode(err, "23503") {
		return fmt.Errorf("%w: that person is not in this home", ErrInvalid)
	}
	if err != nil {
		return fmt.Errorf("tick meal: %w", err)
	}
	return nil
}

// ImportMeals replaces the plan for every day in the pasted menu with that day's meals, in one transaction.
// Days not in the menu are untouched. With dryRun it only counts.
// Args: ctx, meals (validated by the caller: at most MaxMealImportDays days, MaxMealsPerDay per day), actor, dryRun
// Returns: the day and meal counts, and how many of those days already had a plan
// Handles: two imports at once (serialised by a transaction lock), a failure part way (nothing is kept)
func (s *Store) ImportMeals(ctx context.Context, meals []Meal, actor uuid.UUID, dryRun bool) (MealImportResult, error) {
	var result MealImportResult
	days := make([]string, 0, len(meals))
	seen := map[string]bool{}
	for _, meal := range meals {
		if !seen[meal.Day] {
			seen[meal.Day] = true
			days = append(days, meal.Day)
		}
	}
	result.Days, result.Meals = len(days), len(meals)

	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(7340103)"); err != nil {
			return fmt.Errorf("lock meal import: %w", err)
		}
		if err := tx.QueryRow(ctx, "SELECT count(DISTINCT day) FROM home_meals WHERE day = ANY($1::date[])", days).Scan(&result.Replaced); err != nil {
			return fmt.Errorf("count planned days: %w", err)
		}
		if dryRun {
			return nil
		}
		if _, err := tx.Exec(ctx, "DELETE FROM home_meals WHERE day = ANY($1::date[])", days); err != nil {
			return fmt.Errorf("clear planned days: %w", err)
		}
		if err := learnDishes(ctx, tx, meals, actor); err != nil {
			return err
		}
		batch := &pgx.Batch{}
		for index, meal := range meals {
			ingredients, err := encodeIngredients(meal.Ingredients)
			if err != nil {
				return err
			}
			batch.Queue("INSERT INTO home_meals (id, day, slot, name, kcal, protein_g, carbs_g, fat_g, serves, ingredients, sort_order, created_by, dish_id, ordered_in) VALUES ($1, $2::date, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11, $12, (SELECT d.id FROM home_dishes d WHERE d.name_key = $13), $14)", uuid.New(), meal.Day, meal.Slot, meal.Name, meal.Kcal, meal.ProteinG, meal.CarbsG, meal.FatG, meal.Serves, ingredients, index, actor, dishKey(meal.Name), meal.OrderedIn)
		}
		if err := tx.SendBatch(ctx, batch).Close(); err != nil {
			return fmt.Errorf("insert meals: %w", err)
		}
		return nil
	})
	if err != nil {
		return MealImportResult{}, err
	}
	return result, nil
}
