package home

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	mealSuggestPath      = "/v1/meals/suggest"
	mealIdeaAgainPath    = "/v1/meals/suggest/again"
	maxSuggestCallsADay  = 20
	maxIdeaAgainADay     = 30
	maxSuggestFavourites = 10
	maxSuggestWhy        = 140
	maxSuggestWeek       = 40
	maxSuggestTries      = 3
	ideasPerSlot         = 1
	suggestMaxTokens     = 3000
)

// suggestSlots are the slots an empty day is filled in, in the order of the day. Late night is left out: a goal of
// losing fat is never helped by an idea to eat again before bed.
var suggestSlots = []string{"breakfast", "lunch", "snack", "dinner"}

var errSuggestUnavailable = apiError{status: http.StatusServiceUnavailable, Code: "suggest_unavailable", Message: "meal suggestions are not set up on this server"}
var errSuggestFailed = apiError{status: http.StatusBadGateway, Code: "suggest_failed", Message: "could not think of suggestions this time"}
var errIdeaAgainLimit = apiError{status: http.StatusTooManyRequests, Code: "idea_limit", Message: "that is enough new ideas for today, try again tomorrow"}
var errIdeaGone = apiError{status: http.StatusConflict, Code: "idea_gone", Message: "that idea is no longer on the day, pull to refresh"}

const suggestPrompt = `You plan meals for one person who cooks at home in Pune, India. The goal is to eat better, healthier and tastier while reaching their body goal: lose fat down to the goal weight by the goal date (goalBy) while building muscle.
Their goal and figures, as JSON (weights in kilograms, food in kilocalories and grams; missing keys are unknown): %s
Dishes they eat most, so you know their taste: %s
Their plan for %s, one entry per dish with its id, slot, name and the calories and protein of one plate: %s

1. Fill EVERY one of these empty slots with %d real home dish(es) each; never leave one of them out: %s
2. For each dish whose id is in this list, suggest a swap ONLY when a clearly better option exists: healthier for their goal (fewer calories, or more protein for a similar plate) and still tasty and close in spirit, the way Veg Biryani becomes Veg Pulao with raita. When the dish is already a good choice, leave it out. Ids: %s
Already on their week or turned down, so never suggest any of these: %s

Keep the whole day at the daily calorie target (kcalTargetDay) so the week adds up to the weekly pace, and reach the protein target (proteinTargetG) to build muscle: size each idea to the calories and protein the plan still leaves, and give breakfast, lunch and dinner at least 25 g of protein each. Vary the week: a different main protein (paneer, dal, chana, rajma, soya, curd, eggs, chicken, fish, as their diet allows) from day to day. Follow the diet their dishes show: if no meat, fish or egg appears, suggest none. Prefer dishes they already like or close cousins of them. "snack" is evening tea time; "late" is a late-night bite, so keep it light, under 200 kcal.
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

// MealIdeas is a day's answer: dishes for empty slots and better options for planned dishes. Tries counts, per slot,
// the times the model was asked to fill it, so a slot it keeps leaving empty is asked at most maxSuggestTries times.
type MealIdeas struct {
	Fills []MealIdea     `json:"fills"`
	Swaps []MealIdea     `json:"swaps"`
	Tries map[string]int `json:"tries,omitempty"`
}

// toAsk returns the open slots this answer holds no idea for and that still have tries left, in the order given.
func (ideas MealIdeas) toAsk(open []string) []string {
	filled := map[string]bool{}
	for _, fill := range ideas.Fills {
		filled[fill.Slot] = true
	}
	missing := []string{}
	for _, slot := range open {
		if !filled[slot] && ideas.Tries[slot] < maxSuggestTries {
			missing = append(missing, slot)
		}
	}
	return missing
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

// keepUsable drops what no longer fits the day: a fill for a slot that now has a dish, more than ideasPerSlot fills
// or a repeated dish in one slot, a swap for a dish that is gone or already eaten, a second swap for the same dish,
// and a swap that only repeats the dish's name.
func (ideas MealIdeas) keepUsable(empty []string, open map[uuid.UUID]string) MealIdeas {
	usable := MealIdeas{Fills: []MealIdea{}, Swaps: []MealIdea{}}
	wanted := set(empty...)
	perSlot := map[string]int{}
	seen := map[string]bool{}
	pending := make(map[uuid.UUID]string, len(open))
	for id, name := range open {
		pending[id] = name
	}
	for _, fill := range ideas.Fills {
		key := fill.Slot + "|" + strings.ToLower(fill.Name)
		if !wanted[fill.Slot] || perSlot[fill.Slot] == ideasPerSlot || seen[key] {
			continue
		}
		usable.Fills = append(usable.Fills, fill)
		perSlot[fill.Slot]++
		seen[key] = true
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

// SuggestMeals asks the model for fills and swaps on one day, and keeps only ideas that pass a meal's checks. Each
// empty slot and the swaps go out as their own call, all at once, so a day with five open slots takes as long as one.
// Args: input (the day, its dishes, the goal and favourite dishes), empty (slots to fill), swappable (dish ids),
// count (fills per slot), avoid (dish names the answer must not repeat)
// Returns: the parsed ideas (not yet matched to the day); errSuggestFailed only when every call fails
func (v *Vision) SuggestMeals(ctx context.Context, input suggestInput, empty []string, swappable []uuid.UUID, count int, avoid []string) (MealIdeas, error) {
	type ask struct {
		slots []string
		ids   []uuid.UUID
	}
	asks := make([]ask, 0, len(empty)+1)
	for _, slot := range empty {
		asks = append(asks, ask{slots: []string{slot}, ids: []uuid.UUID{}})
	}
	if len(swappable) > 0 {
		asks = append(asks, ask{slots: []string{}, ids: swappable})
	}
	answers := make([]MealIdeas, len(asks))
	failures := make([]error, len(asks))
	var wait sync.WaitGroup
	for index, one := range asks {
		wait.Add(1)
		go func() {
			defer wait.Done()
			answers[index], failures[index] = v.askIdeas(ctx, input, one.slots, one.ids, count, avoid)
		}()
	}
	wait.Wait()
	ideas := MealIdeas{Fills: []MealIdea{}, Swaps: []MealIdea{}}
	answered := 0
	for index, one := range asks {
		if failures[index] != nil {
			continue
		}
		answered++
		for _, fill := range answers[index].Fills {
			if len(one.slots) == 1 && fill.Slot == one.slots[0] {
				ideas.Fills = append(ideas.Fills, fill)
			}
		}
		if len(one.ids) > 0 {
			ideas.Swaps = append(ideas.Swaps, answers[index].Swaps...)
		}
	}
	if answered == 0 && len(asks) > 0 {
		return MealIdeas{}, errSuggestFailed
	}
	return ideas, nil
}

// askIdeas is one model call of SuggestMeals.
// Returns: the parsed fills and swaps; errSuggestFailed when the model errors, refuses or answers nothing parseable
func (v *Vision) askIdeas(ctx context.Context, input suggestInput, empty []string, swappable []uuid.UUID, count int, avoid []string) (MealIdeas, error) {
	goal, _ := json.Marshal(input.Goal)
	favourites, _ := json.Marshal(input.Favourites)
	dishes, _ := json.Marshal(input.Dishes)
	slots, _ := json.Marshal(empty)
	ids, _ := json.Marshal(swappable)
	if avoid == nil {
		avoid = []string{}
	}
	skip, _ := json.Marshal(avoid)
	started := time.Now()
	response, err := v.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:        visionModel,
		MaxTokens:    suggestMaxTokens,
		OutputConfig: anthropic.OutputConfigParam{Effort: anthropic.OutputConfigEffortLow, Format: anthropic.JSONOutputFormatParam{Schema: suggestSchema}},
		Messages:     []anthropic.MessageParam{anthropic.NewUserMessage(anthropic.NewTextBlock(fmt.Sprintf(suggestPrompt, goal, favourites, input.Day, dishes, count, slots, ids, skip)))},
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
	Slot       string         `json:"slot"`
	Name       string         `json:"name"`
	Week       []string       `json:"week"`
}

// suggestDay is one suggest request read against the plan: what to ask, its cache key, and what is open.
type suggestDay struct {
	input suggestInput
	hash  string
	slots []string
	open  map[uuid.UUID]string
	meals []Meal
	week  []string
}

// readSuggest validates a suggest body and reads the day's plan. The dishes always come from the plan, never from
// the app, so the same day, dishes, goal and favourites give the same cache key. Week (dishes on the week's other
// days) only steers variety and is not part of the key.
// Returns: the day, or nil with nothing to do (a past day, or every slot filled and every dish eaten); a 400 for a
// bad day or goal
func (s *Server) readSuggest(r *http.Request, body suggestBody) (*suggestDay, error) {
	day, err := time.Parse("2006-01-02", body.Day)
	if err != nil {
		return nil, badRequest("day must be YYYY-MM-DD")
	}
	goal := map[string]any{}
	if len(body.Goal) > 0 {
		encoded, err := validateFigures(body.Goal)
		if err != nil {
			return nil, err
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
	week := []string{}
	for _, name := range body.Week {
		name = strings.Join(strings.Fields(name), " ")
		if textBetween(name, 1, maxDishNameText) && len(week) < maxSuggestWeek {
			week = append(week, name)
		}
	}
	if day.Before(time.Now().UTC().AddDate(0, 0, -1).Truncate(24 * time.Hour)) {
		return nil, nil
	}
	meals, _, err := s.store.Meals(r.Context(), body.Day, body.Day)
	if err != nil {
		return nil, err
	}
	slots, open := openings(meals, actor(r).ID)
	if len(slots) == 0 && len(open) == 0 {
		return nil, nil
	}
	input := suggestInput{Day: body.Day, Dishes: make([]suggestDish, 0, len(meals)), Goal: goal, Favourites: favourites}
	for _, meal := range meals {
		input.Dishes = append(input.Dishes, suggestDish{ID: meal.ID, Slot: meal.Slot, Name: meal.Name, Kcal: meal.Kcal, ProteinG: meal.ProteinG})
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("encode suggest input: %w", err)
	}
	return &suggestDay{input: input, hash: figuresHash(encoded), slots: slots, open: open, meals: meals, week: week}, nil
}

// suggestMeals answers a day: POST /v1/meals/suggest {day, goal, favourites, week} → {fills, swaps, fresh, pending}.
// Every empty slot gets ideasPerSlot fills. A day is asked once and then served from the store, even after its plan
// changes: filled slots leave the answer. An open slot with no idea (one the model skipped, or one that opened since)
// is asked again, for the missing slots alone and added to the kept answer, at most maxSuggestTries times a slot;
// pending says the app may ask once more. ↻ (suggestAgain) is the way to new ideas. A member gets at most
// maxSuggestCallsADay new days a day, after which the kept answer (or none) is served as it is.
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
	plan, err := s.readSuggest(r, body)
	if err != nil {
		writeError(w, r, err)
		return
	}
	if plan == nil {
		writeJSON(w, http.StatusOK, map[string]any{"fills": []MealIdea{}, "swaps": []MealIdea{}, "fresh": false, "pending": false})
		return
	}
	user := actor(r).ID
	kept, keptHash, err := s.store.MealIdeasForDay(r.Context(), user, body.Day)
	found := err == nil
	if err != nil && !errors.Is(err, ErrNotFound) {
		writeError(w, r, err)
		return
	}
	serveKept := func() {
		usable := kept.keepUsable(plan.slots, plan.open)
		writeJSON(w, http.StatusOK, map[string]any{"fills": usable.Fills, "swaps": usable.Swaps, "fresh": false, "pending": false})
	}
	missing := kept.toAsk(plan.slots)
	if found && len(missing) == 0 {
		serveKept()
		return
	}
	if !found {
		calls, err := s.store.MealIdeasToday(r.Context(), user)
		if err != nil {
			writeError(w, r, err)
			return
		}
		if calls >= maxSuggestCallsADay {
			serveKept()
			return
		}
	}

	swappable := make([]uuid.UUID, 0, len(plan.open))
	for _, meal := range plan.meals {
		if _, ok := plan.open[meal.ID]; ok && !found {
			swappable = append(swappable, meal.ID)
		}
	}
	ideas, err := s.vision.SuggestMeals(r.Context(), plan.input, missing, swappable, ideasPerSlot, plan.week)
	if err != nil {
		log.Printf("[%s] meal suggest failed", middleware.GetReqID(r.Context()))
		writeError(w, r, err)
		return
	}
	fresh := ideas.keepUsable(missing, plan.open)
	tries := map[string]int{}
	for slot, count := range kept.Tries {
		tries[slot] = count
	}
	for _, slot := range missing {
		tries[slot]++
	}
	saved := MealIdeas{Fills: append(kept.Fills, fresh.Fills...), Swaps: fresh.Swaps, Tries: tries}
	hash := plan.hash
	if found {
		saved.Swaps = kept.Swaps
		hash = keptHash
	}
	if err := s.store.SaveMealIdeas(r.Context(), user, hash, body.Day, saved); err != nil {
		writeError(w, r, err)
		return
	}
	usable := saved.keepUsable(plan.slots, plan.open)
	writeJSON(w, http.StatusOK, map[string]any{"fills": usable.Fills, "swaps": usable.Swaps, "fresh": true, "pending": len(saved.toAsk(plan.slots)) > 0})
}

// suggestAgain swaps one idea I did not like for a new one in the same slot:
// POST /v1/meals/suggest/again {day, goal, favourites, week, slot, name} → {fills, swaps, fresh}. It finds the day's kept
// answer; the new dish takes the old one's place there, so the card keeps it after a reload, and ideas for slots
// filled since are kept for the day a slot opens again. The model is told every dish already in that slot, so it never offers one again.
// Handles: no key (503), a bad body (400), an idea or slot no longer on the day (409), maxIdeaAgainADay used (429),
// a model failure or an answer that only repeats (502; nothing is used up)
func (s *Server) suggestAgain(w http.ResponseWriter, r *http.Request) {
	if s.vision == nil {
		writeError(w, r, errSuggestUnavailable)
		return
	}
	var body suggestBody
	if err := decode(r, &body); err != nil {
		writeError(w, r, err)
		return
	}
	if !mealSlots[body.Slot] || !textBetween(body.Name, 1, maxDishNameText) {
		writeError(w, r, badRequest("slot and name must name the idea to replace"))
		return
	}
	plan, err := s.readSuggest(r, body)
	if err != nil {
		writeError(w, r, err)
		return
	}
	if plan == nil {
		writeError(w, r, errIdeaGone)
		return
	}
	user := actor(r).ID
	cached, keptHash, err := s.store.MealIdeasForDay(r.Context(), user, body.Day)
	if errors.Is(err, ErrNotFound) {
		writeError(w, r, errIdeaGone)
		return
	}
	if err != nil {
		writeError(w, r, err)
		return
	}
	current := cached.keepUsable(plan.slots, plan.open)
	position := -1
	shown := []string{}
	for index, fill := range current.Fills {
		if fill.Slot != body.Slot {
			continue
		}
		shown = append(shown, fill.Name)
		if strings.EqualFold(fill.Name, body.Name) {
			position = index
		}
	}
	if position < 0 {
		writeError(w, r, errIdeaGone)
		return
	}
	use, err := s.store.ReserveAIUse(r.Context(), user, aiUseIdeaAgain, maxIdeaAgainADay)
	if err != nil {
		writeError(w, r, err)
		return
	}
	if use == uuid.Nil {
		writeError(w, r, errIdeaAgainLimit)
		return
	}
	ideas, err := s.vision.SuggestMeals(r.Context(), plan.input, []string{body.Slot}, nil, 1, append(append([]string{}, shown...), plan.week...))
	fresh := MealIdea{}
	if err == nil {
		for _, fill := range ideas.Fills {
			repeat := false
			for _, name := range shown {
				repeat = repeat || strings.EqualFold(name, fill.Name)
			}
			if !repeat {
				fresh = fill
				break
			}
		}
	}
	if fresh.Name == "" {
		log.Printf("[%s] meal idea again failed", middleware.GetReqID(r.Context()))
		writeError(w, r, errSuggestFailed)
		return
	}
	current.Fills[position] = fresh
	kept := MealIdeas{Fills: current.Fills, Swaps: current.Swaps, Tries: cached.Tries}
	open := set(plan.slots...)
	for _, fill := range cached.Fills {
		if !open[fill.Slot] {
			kept.Fills = append(kept.Fills, fill)
		}
	}
	if err := s.store.SaveMealIdeas(r.Context(), user, keptHash, body.Day, kept); err != nil {
		writeError(w, r, err)
		return
	}
	if err := s.store.FinishAIUse(r.Context(), use); err != nil {
		log.Printf("[%s] meal idea again: saved but not marked used: %v", middleware.GetReqID(r.Context()), err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"fills": current.Fills, "swaps": current.Swaps, "fresh": true})
}

// MealIdeasForDay returns the newest answer kept for one day and the key it is stored under, or ErrNotFound.
func (s *Store) MealIdeasForDay(ctx context.Context, userID uuid.UUID, day string) (MealIdeas, string, error) {
	var raw []byte
	var inputHash string
	err := s.pool.QueryRow(ctx, "SELECT input_hash, ideas FROM home_meal_ideas WHERE user_id = $1 AND day = $2::date ORDER BY created_at DESC LIMIT 1", userID, day).Scan(&inputHash, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return MealIdeas{}, "", ErrNotFound
	}
	if err != nil {
		return MealIdeas{}, "", fmt.Errorf("read meal ideas: %w", err)
	}
	var ideas MealIdeas
	if err := json.Unmarshal(raw, &ideas); err != nil {
		return MealIdeas{}, "", fmt.Errorf("decode meal ideas: %w", err)
	}
	return ideas, inputHash, nil
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
