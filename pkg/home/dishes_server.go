package home

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
)

const defaultDishSearchLimit = 8

// listDishes answers the Add dish dropdown: ?q=<typed text>&limit=<n>. No q lists the most recently used dishes.
func (s *Server) listDishes(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if !textBetween(query, 0, 120) {
		writeError(w, r, badRequest("q must be at most 120 characters"))
		return
	}
	limit := defaultDishSearchLimit
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > MaxDishesPerSearch {
			writeError(w, r, badRequest("limit must be 1 to "+strconv.Itoa(MaxDishesPerSearch)))
			return
		}
		limit = parsed
	}
	dishes, err := s.store.SearchDishes(r.Context(), query, limit)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"dishes": dishes})
}

type addMealBody struct {
	mealBody
	SaveToLibrary bool `json:"saveToLibrary"`
}

// addMeal puts one dish on one day's slot and teaches the library about it.
// Handles: the same validation as an import row; saveToLibrary decides whether changed numbers replace a known dish's
func (s *Server) addMeal(w http.ResponseWriter, r *http.Request) {
	var body addMealBody
	if err := decode(r, &body); err != nil {
		writeError(w, r, err)
		return
	}
	meal, err := body.mealBody.validate()
	if err != nil {
		writeError(w, r, err)
		return
	}
	saved, err := s.store.AddMeal(r.Context(), meal, actor(r).ID, body.SaveToLibrary)
	if errors.Is(err, ErrSlotFull) {
		writeError(w, r, badRequest(fmt.Sprintf("that slot already has %d dishes", MaxMealsPerDay)))
		return
	}
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, saved)
}
