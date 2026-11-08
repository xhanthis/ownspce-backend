package home

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// dishLibraryJSON is the default dish library: Marathi home dishes with per-person nutrition and
// ingredients for two, generated from the portion table in the task's docs/meals-library.md.
//
//go:embed dish_library.json
var dishLibraryJSON []byte

// libraryDish is one row of the embedded library file.
type libraryDish struct {
	Name        string           `json:"name"`
	Kcal        int              `json:"kcal"`
	ProteinG    int              `json:"proteinG"`
	CarbsG      int              `json:"carbsG"`
	FatG        int              `json:"fatG"`
	Serves      int              `json:"serves"`
	Ingredients []ingredientBody `json:"ingredients"`
}

// defaultDishes decodes the embedded library and runs every row through the same checks a posted meal gets.
// Returns: the dishes in file order, or the first row that fails and why
func defaultDishes() ([]Meal, error) {
	var rows []libraryDish
	if err := json.Unmarshal(dishLibraryJSON, &rows); err != nil {
		return nil, fmt.Errorf("dish library: %w", err)
	}
	seen := map[string]bool{}
	dishes := make([]Meal, 0, len(rows))
	for index, row := range rows {
		body := mealBody{Day: "2000-01-01", Slot: "lunch", Name: row.Name, Kcal: row.Kcal, ProteinG: row.ProteinG, CarbsG: row.CarbsG, FatG: row.FatG, Serves: row.Serves, Ingredients: row.Ingredients}
		meal, err := body.validate()
		if err != nil {
			return nil, fmt.Errorf("dish library row %d (%q): %w", index+1, row.Name, err)
		}
		key := dishKey(meal.Name)
		if seen[key] {
			return nil, fmt.Errorf("dish library row %d (%q): duplicate name", index+1, row.Name)
		}
		seen[key] = true
		dishes = append(dishes, meal)
	}
	return dishes, nil
}

// SeedDishes adds every default dish the library does not have yet. A name already there, whether from a
// menu import or an earlier seed, is left exactly as it is, so edits made in the app survive every restart.
// Seeded rows carry no owner, zero uses and an old last-used date, so dishes the household has really cooked
// stay ahead of them in the dropdown.
// Open runs it whenever the build's schema fingerprint changes, so a normal cold start never touches it.
// Returns: how many dishes were added this time
// Handles: two instances starting together (ON CONFLICT DO NOTHING), a bad library file (refused whole, nothing written)
func (s *Store) SeedDishes(ctx context.Context) (int, error) {
	added := 0
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		added, err = seedDishes(ctx, tx)
		return err
	})
	return added, err
}

func seedDishes(ctx context.Context, tx pgx.Tx) (int, error) {
	dishes, err := defaultDishes()
	if err != nil {
		return 0, err
	}
	batch := &pgx.Batch{}
	for _, dish := range dishes {
		ingredients, err := encodeIngredients(dish.Ingredients)
		if err != nil {
			return 0, err
		}
		batch.Queue("INSERT INTO home_dishes (id, name, name_key, kcal, protein_g, carbs_g, fat_g, serves, ingredients, times_used, last_used_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, 0, '2000-01-01') ON CONFLICT (name_key) DO NOTHING", uuid.New(), strings.Join(strings.Fields(dish.Name), " "), dishKey(dish.Name), dish.Kcal, dish.ProteinG, dish.CarbsG, dish.FatG, dish.Serves, ingredients)
	}
	results := tx.SendBatch(ctx, batch)
	defer results.Close()
	added := 0
	for range dishes {
		tag, err := results.Exec()
		if err != nil {
			return 0, fmt.Errorf("seed dishes: %w", err)
		}
		added += int(tag.RowsAffected())
	}
	return added, nil
}
