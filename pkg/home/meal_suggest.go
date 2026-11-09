package home

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	mealSuggestPath      = "/v1/meals/suggest"
	maxSuggestCallsADay  = 20
	maxSuggestFavourites = 10
	maxSuggestWhy        = 140
	suggestMaxTokens     = 3000
)

// suggestSlots are the slots an empty day is filled in; a snack or late-night plate is never pushed on anyone.
var suggestSlots = []string{"breakfast", "lunch", "dinner"}

var errSuggestUnavailable = apiError{status: http.StatusServiceUnavailable, Code: "suggest_unavailable", Message: "meal suggestions are not set up on this server"}
var errSuggestFailed = apiError{status: http.StatusBadGateway, Code: "suggest_failed", Message: "could not think of suggestions this time"}

const suggestPrompt = `You plan meals for one person who cooks at home in Pune, India. The goal is to eat better, healthier and tastier while reaching their body goal.
Their goal and figures, as JSON (weights in kilograms, food in kilocalories and grams; missing keys are unknown): %s
Dishes they eat most, so you know their taste: %s
Their plan for %s, one entry per dish with its id, slot, name and the calories and protein of one plate: %s

1. For each of these empty slots, suggest ONE real home dish to fill it: %s
2. For each dish whose id is in this list, suggest a swap ONLY when a clearly better option exists: healthier for their goal (fewer calories, or more protein for a similar plate) and still tasty and close in spirit, the way Veg Biryani becomes Veg Pulao with raita. When the dish is already a good choice, leave it out. Ids: %s

Keep the whole day near what their goal needs and push protein toward the target. Follow the diet their dishes show: if no meat, fish or egg appears, suggest none. Prefer dishes they already like or close cousins of them.
Give calories, protein, carbs and fat for ONE normal adult serving. List the ingredients to cook it for TWO people with an amount the kitchen can count (grams or kilograms, millilitres or litres, or pieces), skipping spices, salt, oil and other pantry staples, at most 12. "name" is a plain dish name of at most 50 characters. "why" is one short plain sentence of at most 100 characters naming the gain, such as "120 kcal lighter, same comfort". Use only the slots and ids given above; empty lists are fine.`

// suggestSchema is the JSON a suggestion answer must follow: fills for empty slots and swaps for planned dishes,
// each a full dish (the same shape an estimate has) plus its name, a reason, and the slot or dish it is for.
var suggestSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"fills": map[string]any{"type": "array", "items": dishSchemaWith("name", "why", "slot")},
		"swaps": map[string]any{"type": "array", "items": dishSchemaWith("name", "why", "mealId")},
	},
	"required":             []string{"fills", "swaps"},
	"additionalProperties": false,
}

// MealIdea is one suggested dish, ready to add or to put in place of a planned one: per-plate nutrition and
// ingredients for two, like a library dish. Slot is set on a fill, MealID on a swap.
type MealIdea struct {
	Slot        string       `json:"slot,omitempty"`
	MealID      *uuid.UUID   `json:"mealId,omitempty"`
	Name        string       `json:"name"`
	Kcal        int          `json:"kcal"`
	ProteinG    int          `json:"proteinG"`
	CarbsG      int          `json:"carbsG"`
	FatG        int          `json:"fatG"`
	Serves      int          `json:"serves"`
	Ingredients []Ingredient `json:"ingredients"`
	Why         string       `json:"why"`
}

// MealIdeas is a day's answer: dishes for empty slots and better options for planned dishes.
type MealIdeas struct {
	Fills []MealIdea `json:"fills"`
	Swaps []MealIdea `json:"swaps"`
}

// suggestDish is what the model sees of one planned dish.
type suggestDish struct {
	ID       uuid.UUID `json:"id"`
	Slot     string    `json:"slot"`
	Name     string    `json:"name"`
	Kcal     int       `json:"kcal"`
	ProteinG int       `json:"proteinG"`
}

// suggestInput is everything an answer depends on; its hash keys the cache, so ticking a dish never asks again.
type suggestInput struct {
	Day        string         `json:"day"`
	Dishes     []suggestDish  `json:"dishes"`
	Goal       map[string]any `json:"goal"`
	Favourites []string       `json:"favourites"`
}

// openings works out which slots of a day are empty and which planned dishes this person has not eaten yet.
// Returns: the empty suggestSlots in order, and the ids of dishes still open to a swap
func openings(meals []Meal, userID uuid.UUID) ([]string, map[uuid.UUID]string) {
	filled := map[string]bool{}
	open := map[uuid.UUID]string{}
	for _, meal := range meals {
		filled[meal.Slot] = true
		eaten := false
		for _, tick := range meal.Ticks {
			if tick.UserID == userID {
				eaten = true
			}
		}
		if !eaten {
			open[meal.ID] = meal.Name
		}
	}
	empty := []string{}
	for _, slot := range suggestSlots {
		if !filled[slot] {
			empty = append(empty, slot)
		}
	}
	return empty, open
}

// keepUsable drops what no longer fits the day: a fill for a slot that now has a dish, a swap for a dish that is
// gone or already eaten, a second idea for the same slot or dish, and a swap that only repeats the dish's name.
func (ideas MealIdeas) keepUsable(empty []string, open map[uuid.UUID]string) MealIdeas {
	usable := MealIdeas{Fills: []MealIdea{}, Swaps: []MealIdea{}}
	wanted := set(empty...)
	pending := make(map[uuid.UUID]string, len(open))
	for id, name := range open {
		pending[id] = name
	}
	for _, fill := range ideas.Fills {
		if wanted[fill.Slot] {
			usable.Fills = append(usable.Fills, fill)
			delete(wanted, fill.Slot)
		}
	}
	for _, swap := range ideas.Swaps {
		if swap.MealID == nil {
			continue
		}
		current, ok := pending[*swap.MealID]
		if !ok || strings.EqualFold(strings.TrimSpace(current), swap.Name) {
			continue
		}
		usable.Swaps = append(usable.Swaps, swap)
		delete(pending, *swap.MealID)
	}
	return usable
}

// ideaFromReply runs one suggested dish through the same checks an estimate gets, then reads its reason and target.
// Returns: the idea, or why it is unusable
func ideaFromReply(raw json.RawMessage) (MealIdea, error) {
	estimate, name, err := dishFromReply(string(raw), "")
	if err != nil {
		return MealIdea{}, err
	}
	var extra struct {
		Why, Slot, MealID string
	}
	if err := json.Unmarshal(raw, &extra); err != nil {
		return MealIdea{}, fmt.Errorf("reply was not the expected shape: %w", err)
	}
	why := strings.Join(strings.Fields(extra.Why), " ")
	if utf8.RuneCountInString(why) > maxSuggestWhy {
		why = strings.TrimSpace(string([]rune(why)[:maxSuggestWhy]))
	}
	idea := MealIdea{Slot: extra.Slot, Name: name, Kcal: estimate.Kcal, ProteinG: estimate.ProteinG, CarbsG: estimate.CarbsG, FatG: estimate.FatG, Serves: estimate.Serves, Ingredients: estimate.Ingredients, Why: why}
	if extra.MealID != "" {
		id, err := uuid.Parse(extra.MealID)
		if err != nil {
			return MealIdea{}, errors.New("swap named no dish")
		}
		idea.MealID = &id
	}
	return idea, nil
}

// SuggestMeals asks the model for fills and swaps on one day, and keeps only ideas that pass a meal's checks.
// Args: input (the day, its dishes, the goal and favourite dishes), empty (slots to fill), swappable (dish ids)
// Returns: the parsed ideas (not yet matched to the day); errSuggestFailed when the model errors, refuses or
// answers nothing parseable
func (v *Vision) SuggestMeals(ctx context.Context, input suggestInput, empty []string, swappable []uuid.UUID) (MealIdeas, error) {
	goal, _ := json.Marshal(input.Goal)
	favourites, _ := json.Marshal(input.Favourites)
	dishes, _ := json.Marshal(input.Dishes)
	slots, _ := json.Marshal(empty)
	ids, _ := json.Marshal(swappable)
	started := time.Now()
	response, err := v.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:        visionModel,
		MaxTokens:    suggestMaxTokens,
		OutputConfig: anthropic.OutputConfigParam{Effort: anthropic.OutputConfigEffortLow, Format: anthropic.JSONOutputFormatParam{Schema: suggestSchema}},
		Messages:     []anthropic.MessageParam{anthropic.NewUserMessage(anthropic.NewTextBlock(fmt.Sprintf(suggestPrompt, goal, favourites, input.Day, dishes, slots, ids)))},
	})
	if err != nil {
		log.Printf("meal suggest: model call failed after %s: %v", time.Since(started).Round(time.Millisecond), err)
		return MealIdeas{}, errSuggestFailed
	}
	if response.StopReason == anthropic.StopReasonRefusal {
		log.Printf("meal suggest: model declined")
		return MealIdeas{}, errSuggestFailed
	}
	var parsed struct {
		Fills []json.RawMessage
		Swaps []json.RawMessage
	}
	if err := json.Unmarshal([]byte(replyText(response)), &parsed); err != nil {
		log.Printf("meal suggest: reply was not the expected shape: %v", err)
		return MealIdeas{}, errSuggestFailed
	}
	ideas := MealIdeas{Fills: []MealIdea{}, Swaps: []MealIdea{}}
	for _, raw := range parsed.Fills {
		if idea, err := ideaFromReply(raw); err == nil && idea.MealID == nil {
			ideas.Fills = append(ideas.Fills, idea)
		}
	}
	for _, raw := range parsed.Swaps {
		if idea, err := ideaFromReply(raw); err == nil && idea.MealID != nil {
			idea.Slot = ""
			ideas.Swaps = append(ideas.Swaps, idea)
		}
	}
	log.Printf("meal suggest: ok in %s, %d fills, %d swaps, %d in / %d out tokens", time.Since(started).Round(time.Millisecond), len(ideas.Fills), len(ideas.Swaps), response.Usage.InputTokens, response.Usage.OutputTokens)
	return ideas, nil
}

type suggestBody struct {
	Day        string         `json:"day"`
	Goal       map[string]any `json:"goal"`
	Favourites []string       `json:"favourites"`
}

// suggestMeals answers a day card: POST /v1/meals/suggest {day, goal, favourites} → {fills, swaps, fresh}.
// The day's dishes are read from the plan, never trusted from the app. The same day, dishes, goal and favourites
// are asked once and then served from the store; a member gets at most maxSuggestCallsADay fresh answers a day,
// after which an uncached day answers with no ideas.
// Handles: no key on the server (503), a bad day or goal (400), a past day or a full day (no ideas, no model call),
// a model failure (502)
func (s *Server) suggestMeals(w http.ResponseWriter, r *http.Request) {
	if s.vision == nil {
		writeError(w, r, errSuggestUnavailable)
		return
	}
	var body suggestBody
	if err := decode(r, &body); err != nil {
		writeError(w, r, err)
		return
	}
	day, err := time.Parse("2006-01-02", body.Day)
	if err != nil {
		writeError(w, r, badRequest("day must be YYYY-MM-DD"))
		return
	}
	goal := map[string]any{}
	if len(body.Goal) > 0 {
		encoded, err := validateFigures(body.Goal)
		if err != nil {
			writeError(w, r, err)
			return
		}
		_ = json.Unmarshal(encoded, &goal)
	}
	favourites := []string{}
	for _, name := range body.Favourites {
		name = strings.Join(strings.Fields(name), " ")
		if textBetween(name, 1, maxDishNameText) && len(favourites) < maxSuggestFavourites {
			favourites = append(favourites, name)
		}
	}

	empty := MealIdeas{Fills: []MealIdea{}, Swaps: []MealIdea{}}
	if day.Before(time.Now().UTC().AddDate(0, 0, -1).Truncate(24 * time.Hour)) {
		writeJSON(w, http.StatusOK, map[string]any{"fills": empty.Fills, "swaps": empty.Swaps, "fresh": false})
		return
	}
	user := actor(r).ID
	meals, _, err := s.store.Meals(r.Context(), body.Day, body.Day)
	if err != nil {
		writeError(w, r, err)
		return
	}
	slots, open := openings(meals, user)
	if len(slots) == 0 && len(open) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"fills": empty.Fills, "swaps": empty.Swaps, "fresh": false})
		return
	}

	input := suggestInput{Day: body.Day, Dishes: make([]suggestDish, 0, len(meals)), Goal: goal, Favourites: favourites}
	for _, meal := range meals {
		input.Dishes = append(input.Dishes, suggestDish{ID: meal.ID, Slot: meal.Slot, Name: meal.Name, Kcal: meal.Kcal, ProteinG: meal.ProteinG})
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		writeError(w, r, fmt.Errorf("encode suggest input: %w", err))
		return
	}
	hash := figuresHash(encoded)
	if cached, err := s.store.MealIdeas(r.Context(), user, hash); err == nil {
		usable := cached.keepUsable(slots, open)
		writeJSON(w, http.StatusOK, map[string]any{"fills": usable.Fills, "swaps": usable.Swaps, "fresh": false})
		return
	} else if !errors.Is(err, ErrNotFound) {
		writeError(w, r, err)
		return
	}
	calls, err := s.store.MealIdeasToday(r.Context(), user)
	if err != nil {
		writeError(w, r, err)
		return
	}
	if calls >= maxSuggestCallsADay {
		writeJSON(w, http.StatusOK, map[string]any{"fills": empty.Fills, "swaps": empty.Swaps, "fresh": false})
		return
	}

	swappable := make([]uuid.UUID, 0, len(open))
	for _, meal := range meals {
		if _, ok := open[meal.ID]; ok {
			swappable = append(swappable, meal.ID)
		}
	}
	ideas, err := s.vision.SuggestMeals(r.Context(), input, slots, swappable)
	if err != nil {
		log.Printf("[%s] meal suggest failed", middleware.GetReqID(r.Context()))
		writeError(w, r, err)
		return
	}
	usable := ideas.keepUsable(slots, open)
	if err := s.store.SaveMealIdeas(r.Context(), user, hash, body.Day, usable); err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"fills": usable.Fills, "swaps": usable.Swaps, "fresh": true})
}

// MealIdeas returns the ideas kept for one exact suggest input, or ErrNotFound.
func (s *Store) MealIdeas(ctx context.Context, userID uuid.UUID, inputHash string) (MealIdeas, error) {
	var raw []byte
	err := s.pool.QueryRow(ctx, "SELECT ideas FROM home_meal_ideas WHERE user_id = $1 AND input_hash = $2", userID, inputHash).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return MealIdeas{}, ErrNotFound
	}
	if err != nil {
		return MealIdeas{}, fmt.Errorf("read meal ideas: %w", err)
	}
	var ideas MealIdeas
	if err := json.Unmarshal(raw, &ideas); err != nil {
		return MealIdeas{}, fmt.Errorf("decode meal ideas: %w", err)
	}
	return ideas, nil
}

// MealIdeasToday counts the answers written for this member since midnight UTC, for the daily model-call cap.
func (s *Store) MealIdeasToday(ctx context.Context, userID uuid.UUID) (int, error) {
	var count int
	if err := s.pool.QueryRow(ctx, "SELECT count(*) FROM home_meal_ideas WHERE user_id = $1 AND created_at >= date_trunc('day', now())", userID).Scan(&count); err != nil {
		return 0, fmt.Errorf("count meal ideas: %w", err)
	}
	return count, nil
}

// SaveMealIdeas keeps the ideas for one suggest input. Writing the same input twice keeps the newer answer.
func (s *Store) SaveMealIdeas(ctx context.Context, userID uuid.UUID, inputHash, day string, ideas MealIdeas) error {
	encoded, err := json.Marshal(ideas)
	if err != nil {
		return fmt.Errorf("encode meal ideas: %w", err)
	}
	if _, err := s.pool.Exec(ctx, "INSERT INTO home_meal_ideas (user_id, input_hash, day, ideas) VALUES ($1, $2, $3::date, $4::jsonb) ON CONFLICT (user_id, input_hash) DO UPDATE SET ideas = EXCLUDED.ideas, created_at = now()", userID, inputHash, day, string(encoded)); err != nil {
		return fmt.Errorf("save meal ideas: %w", err)
	}
	return nil
}
