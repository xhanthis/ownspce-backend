package home

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

const (
	mealImportPath = "/v1/meals/import"
	// maxMealImportBytes fits the largest menu the caps allow: 60 days of 10 meals with 40 ingredients each.
	maxMealImportBytes = 4 << 20
	maxKcal            = 5000
	maxGrams          = 1000
	maxServes         = 20
	maxIngredients    = 40
	maxIngredientName = 80
	maxIngredientQty  = 40
	maxLinkLength     = 500
)

var mealSlots = set("breakfast", "lunch", "snack", "dinner")

type ingredientBody struct {
	Name string `json:"name"`
	Qty  string `json:"qty"`
	Link string `json:"link"`
}

type mealBody struct {
	Day         string           `json:"day"`
	Slot        string           `json:"slot"`
	Name        string           `json:"name"`
	Kcal        int              `json:"kcal"`
	ProteinG    int              `json:"proteinG"`
	CarbsG      int              `json:"carbsG"`
	FatG        int              `json:"fatG"`
	Serves      int              `json:"serves"`
	Ingredients []ingredientBody `json:"ingredients"`
}

// validate checks one meal and returns it trimmed. A missing serves count means two.
// Handles: links must be https, so a pasted answer cannot smuggle a javascript: or custom-scheme link into the app
func (b mealBody) validate() (Meal, error) {
	name := strings.TrimSpace(b.Name)
	serves := b.Serves
	if serves == 0 {
		serves = 2
	}
	switch {
	case !validDate(b.Day):
		return Meal{}, badRequest("day must be a yyyy-mm-dd date")
	case !mealSlots[b.Slot]:
		return Meal{}, badRequest("slot must be breakfast, lunch, snack or dinner")
	case !textBetween(name, 1, 120):
		return Meal{}, badRequest("name must be 1 to 120 characters")
	case b.Kcal < 0 || b.Kcal > maxKcal:
		return Meal{}, badRequest(fmt.Sprintf("kcal must be 0 to %d", maxKcal))
	case b.ProteinG < 0 || b.ProteinG > maxGrams || b.CarbsG < 0 || b.CarbsG > maxGrams || b.FatG < 0 || b.FatG > maxGrams:
		return Meal{}, badRequest(fmt.Sprintf("protein, carbs and fat must be 0 to %d grams", maxGrams))
	case serves < 1 || serves > maxServes:
		return Meal{}, badRequest(fmt.Sprintf("serves must be 1 to %d", maxServes))
	case len(b.Ingredients) > maxIngredients:
		return Meal{}, badRequest(fmt.Sprintf("at most %d ingredients per meal", maxIngredients))
	}
	ingredients := make([]Ingredient, 0, len(b.Ingredients))
	for index, raw := range b.Ingredients {
		ingredient := Ingredient{Name: strings.TrimSpace(raw.Name), Qty: strings.TrimSpace(raw.Qty), Link: strings.TrimSpace(raw.Link)}
		switch {
		case !textBetween(ingredient.Name, 1, maxIngredientName):
			return Meal{}, badRequest(fmt.Sprintf("ingredient %d needs a name of at most %d characters", index+1, maxIngredientName))
		case !textBetween(ingredient.Qty, 0, maxIngredientQty):
			return Meal{}, badRequest(fmt.Sprintf("ingredient %d: quantity must be at most %d characters", index+1, maxIngredientQty))
		case ingredient.Link != "" && !validLink(ingredient.Link):
			return Meal{}, badRequest(fmt.Sprintf("ingredient %d: link must be an https address", index+1))
		}
		ingredients = append(ingredients, ingredient)
	}
	return Meal{Day: b.Day, Slot: b.Slot, Name: name, Kcal: b.Kcal, ProteinG: b.ProteinG, CarbsG: b.CarbsG, FatG: b.FatG, Serves: serves, Ingredients: ingredients}, nil
}

func validLink(link string) bool {
	if len(link) > maxLinkLength || !textBetween(link, 1, maxLinkLength) {
		return false
	}
	parsed, err := url.Parse(link)
	return err == nil && parsed.Scheme == "https" && parsed.Host != ""
}

func (s *Server) listMeals(w http.ResponseWriter, r *http.Request) {
	from, to := r.URL.Query().Get("from"), r.URL.Query().Get("to")
	if !validDate(from) || !validDate(to) || from > to {
		writeError(w, r, badRequest("from and to must be yyyy-mm-dd dates, from not after to"))
		return
	}
	meals, truncated, err := s.store.Meals(r.Context(), from, to)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"meals": meals, "truncated": truncated})
}

type mealDayBody struct {
	Day   string     `json:"day"`
	Meals []mealBody `json:"meals"`
}

type mealImportBody struct {
	Days   []mealDayBody `json:"days"`
	DryRun bool          `json:"dryRun"`
}

// importMeals replaces the plan for the pasted days, or with dryRun only counts what would change.
// Handles: an empty or oversized menu, a bad meal (named by day and position), the same day listed twice
func (s *Server) importMeals(w http.ResponseWriter, r *http.Request) {
	var body mealImportBody
	if err := decode(r, &body); err != nil {
		writeError(w, r, err)
		return
	}
	if len(body.Days) == 0 || len(body.Days) > MaxMealImportDays {
		writeError(w, r, badRequest(fmt.Sprintf("paste between 1 and %d days at a time", MaxMealImportDays)))
		return
	}
	meals := make([]Meal, 0, len(body.Days)*3)
	seen := map[string]bool{}
	for _, day := range body.Days {
		switch {
		case !validDate(day.Day):
			writeError(w, r, badRequest(fmt.Sprintf("day %q is not a yyyy-mm-dd date", day.Day)))
			return
		case seen[day.Day]:
			writeError(w, r, badRequest(fmt.Sprintf("%s is listed twice", day.Day)))
			return
		case len(day.Meals) == 0 || len(day.Meals) > MaxMealsPerDay:
			writeError(w, r, badRequest(fmt.Sprintf("%s needs 1 to %d meals", day.Day, MaxMealsPerDay)))
			return
		}
		seen[day.Day] = true
		for index, row := range day.Meals {
			row.Day = day.Day
			meal, err := row.validate()
			if err != nil {
				var invalid apiError
				if errors.As(err, &invalid) {
					err = badRequest(fmt.Sprintf("%s, meal %d: %s", day.Day, index+1, invalid.Message))
				}
				writeError(w, r, err)
				return
			}
			meals = append(meals, meal)
		}
	}
	result, err := s.store.ImportMeals(r.Context(), meals, actor(r).ID, body.DryRun)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) replaceMeal(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, r, errNotFound)
		return
	}
	var body mealBody
	if err := decode(r, &body); err != nil {
		writeError(w, r, err)
		return
	}
	meal, err := body.validate()
	if err != nil {
		writeError(w, r, err)
		return
	}
	saved, err := s.store.ReplaceMeal(r.Context(), id, meal)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, saved)
}

func (s *Server) removeMeal(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, r, errNotFound)
		return
	}
	if err := s.store.RemoveMeal(r.Context(), id); err != nil {
		writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// tickMeal marks a meal as eaten by the signed-in member (PUT) or clears that mark (DELETE).
func (s *Server) tickMeal(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, r, errNotFound)
		return
	}
	if err := s.store.TickMeal(r.Context(), id, actor(r).ID, r.Method == http.MethodPut); err != nil {
		writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
