package home

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
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
	SaveToLibrary bool       `json:"saveToLibrary"`
	Eaters        []tickBody `json:"eaters"`
}

// eaterTicks turns the eaters into ticks: each a member of this home at an offered plate size, no member twice, and
// no more rows than the home can hold. An eater without a userId is the caller.
func (b addMealBody) eaterTicks(self uuid.UUID) ([]MealTick, error) {
	if len(b.Eaters) > maxMembers {
		return nil, badRequest(fmt.Sprintf("at most %d eaters", maxMembers))
	}
	ticks := make([]MealTick, 0, len(b.Eaters))
	seen := map[uuid.UUID]bool{}
	for _, eater := range b.Eaters {
		who, portion, err := eater.validate(self)
		if err != nil {
			return nil, err
		}
		if seen[who] {
			return nil, badRequest("each person can be listed once")
		}
		seen[who] = true
		ticks = append(ticks, MealTick{UserID: who, Portion: portion})
	}
	return ticks, nil
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
	eaters, err := body.eaterTicks(actor(r).ID)
	if err != nil {
		writeError(w, r, err)
		return
	}
	saved, err := s.store.AddMeal(r.Context(), meal, actor(r).ID, body.SaveToLibrary, eaters)
	switch {
	case errors.Is(err, ErrSlotFull):
		writeError(w, r, badRequest(fmt.Sprintf("that slot already has %d dishes", MaxMealsPerDay)))
		return
	case errors.Is(err, ErrInvalid):
		writeError(w, r, badRequest("that person is not in this home"))
		return
	case err != nil:
		writeError(w, r, err)
		return
	}
	if len(eaters) > 0 {
		if _, err := s.store.CookMeal(r.Context(), saved.ID, actor(r).ID); err != nil {
			log.Printf("request %s: meal %s saved, stock not taken: %v", middleware.GetReqID(r.Context()), saved.ID, err)
		}
	}
	writeJSON(w, http.StatusCreated, saved)
}
