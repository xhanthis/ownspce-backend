package home

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
)

const (
	vitPath      = "/v1/vit"
	maxVitADay   = 40
	maxVitTurns  = 20
	maxVitText   = 2000
	maxVitReply  = 4000
	maxVitDishes = 3
	vitMaxTokens = 3000
	vitDaysBack  = 7

	aiUseVit       = "vit"
	aiUseIdeaAgain = "idea_again"
)

var errVitUnavailable = apiError{status: http.StatusServiceUnavailable, Code: "vit_unavailable", Message: "Vit is not set up on this server"}
var errVitFailed = apiError{status: http.StatusBadGateway, Code: "vit_failed", Message: "Vit could not answer this time, try again"}
var errVitLimit = apiError{status: http.StatusTooManyRequests, Code: "vit_limit", Message: fmt.Sprintf("you have used all %d Vit messages for today, Vit is back after midnight", maxVitADay)}

var indiaTime = time.FixedZone("IST", 5*60*60+30*60)

const vitPrompt = `You are Vit, %s's personal dietician, fitness coach and home chef in one. They live in Pune, India and cook at home with family.
It is %s, India time.
Their goal and figures, as JSON (weights in kilograms, food in kilocalories and grams; missing keys are unknown): %s
Their meals from %s to %s, one entry per dish: day, slot, name, the calories, protein, carbs and fat of one plate, and "ate" (portions they ate; 0 means planned, not eaten yet): %s
Slots are breakfast, lunch, snack (evening tea time), dinner and late (late night).

Answer what they ask about food, nutrition, cooking, exercise and their progress, using their own numbers above. Be warm, direct and brief: at most 120 words unless they ask for a recipe or a plan. Write plain text only: no markdown, no asterisks, no tables, no headings; short lines are fine. Give numbers for one normal adult serving.
When you recommend or compare specific dishes, also list them (at most 3) in "dishes": "name" a plain dish name of at most 50 characters, its calories, protein, carbs and fat, "slot" the slot it fits best from now on today, "why" one short sentence of at most 100 characters, and the ingredients to cook it for TWO people with an amount the kitchen can count (grams or kilograms, millilitres or litres, or pieces), skipping spices, salt, oil and other pantry staples, at most 12. Otherwise "dishes" is empty.
Never diagnose; for a medical condition, suggest seeing a doctor. Anything off topic gets one friendly line steering back to food and fitness.`

// vitSchema is the JSON a Vit answer must follow: the reply text and the dishes it recommends or compares.
var vitSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"reply":  map[string]any{"type": "string"},
		"dishes": map[string]any{"type": "array", "items": dishSchemaWith("name", "why", "slot")},
	},
	"required":             []string{"reply", "dishes"},
	"additionalProperties": false,
}

// VitTurn is one message of a Vit conversation, as the app keeps it.
type VitTurn struct {
	Role string `json:"role"`
	Text string `json:"text"`
}

// VitAnswer is Vit's reply and the dishes it names, ready to add to the plan like a suggestion.
type VitAnswer struct {
	Reply  string     `json:"reply"`
	Dishes []MealIdea `json:"dishes"`
}

// vitMeal is what Vit sees of one planned or eaten dish.
type vitMeal struct {
	Day      string  `json:"day"`
	Slot     string  `json:"slot"`
	Name     string  `json:"name"`
	Kcal     int     `json:"kcal"`
	ProteinG int     `json:"proteinG"`
	CarbsG   int     `json:"carbsG"`
	FatG     int     `json:"fatG"`
	Ate      float64 `json:"ate"`
}

// AskVit sends a conversation to the model with my figures and recent meals as its brief.
// Args: name (who Vit talks to), now (the clock, read in India time), goal (my figures), meals (the days around
// now), turns (the conversation, oldest first, ending with my question)
// Returns: the reply and at most maxVitDishes dishes that pass a meal's checks; errVitFailed when the model errors,
// refuses or answers nothing usable
func (v *Vision) AskVit(ctx context.Context, name string, now time.Time, goal map[string]any, meals []vitMeal, turns []VitTurn) (VitAnswer, error) {
	figures, _ := json.Marshal(goal)
	plates, _ := json.Marshal(meals)
	local := now.In(indiaTime)
	from := local.AddDate(0, 0, -vitDaysBack).Format("2006-01-02")
	to := local.AddDate(0, 0, 1).Format("2006-01-02")
	system := fmt.Sprintf(vitPrompt, name, local.Format("Monday 2 January 2006, 15:04"), figures, from, to, plates)
	messages := make([]anthropic.MessageParam, 0, len(turns))
	for _, turn := range turns {
		if turn.Role == "assistant" {
			messages = append(messages, anthropic.NewAssistantMessage(anthropic.NewTextBlock(turn.Text)))
		} else {
			messages = append(messages, anthropic.NewUserMessage(anthropic.NewTextBlock(turn.Text)))
		}
	}
	started := time.Now()
	response, err := v.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:        visionModel,
		MaxTokens:    vitMaxTokens,
		System:       []anthropic.TextBlockParam{{Text: system}},
		OutputConfig: anthropic.OutputConfigParam{Effort: anthropic.OutputConfigEffortLow, Format: anthropic.JSONOutputFormatParam{Schema: vitSchema}},
		Messages:     messages,
	})
	if err != nil {
		log.Printf("vit: model call failed after %s: %v", time.Since(started).Round(time.Millisecond), err)
		return VitAnswer{}, errVitFailed
	}
	if response.StopReason == anthropic.StopReasonRefusal {
		log.Printf("vit: model declined")
		return VitAnswer{}, errVitFailed
	}
	var parsed struct {
		Reply  string
		Dishes []json.RawMessage
	}
	if err := json.Unmarshal([]byte(replyText(response)), &parsed); err != nil {
		log.Printf("vit: reply was not the expected shape: %v", err)
		return VitAnswer{}, errVitFailed
	}
	reply := strings.TrimSpace(parsed.Reply)
	if reply == "" {
		log.Printf("vit: empty reply")
		return VitAnswer{}, errVitFailed
	}
	if utf8.RuneCountInString(reply) > maxVitReply {
		reply = strings.TrimSpace(string([]rune(reply)[:maxVitReply]))
	}
	answer := VitAnswer{Reply: reply, Dishes: []MealIdea{}}
	for _, raw := range parsed.Dishes {
		dish, err := ideaFromReply(raw)
		if err != nil || dish.MealID != nil {
			continue
		}
		if !mealSlots[dish.Slot] {
			dish.Slot = ""
		}
		answer.Dishes = append(answer.Dishes, dish)
		if len(answer.Dishes) == maxVitDishes {
			break
		}
	}
	log.Printf("vit: ok in %s, %d dishes, %d in / %d out tokens", time.Since(started).Round(time.Millisecond), len(answer.Dishes), response.Usage.InputTokens, response.Usage.OutputTokens)
	return answer, nil
}

type vitBody struct {
	Messages []VitTurn      `json:"messages"`
	Goal     map[string]any `json:"goal"`
}

// askVit answers one message: POST /v1/vit {messages, goal} → {reply, dishes, left}. The app keeps the conversation
// and sends it whole; the meals come from the plan. Each member gets maxVitADay answers a day (India time), counted
// before the model is called so two quick sends cannot pass the cap; a failed answer gives its count back.
// Handles: no key (503), a bad conversation or goal (400), the day's cap used (429), a model failure (502), a store
// error after the answer (the answer still goes back, without "left"; the reservation lapses in a minute)
func (s *Server) askVit(w http.ResponseWriter, r *http.Request) {
	if s.vision == nil {
		writeError(w, r, errVitUnavailable)
		return
	}
	var body vitBody
	if err := decode(r, &body); err != nil {
		writeError(w, r, err)
		return
	}
	turns, err := cleanVitTurns(body.Messages)
	if err != nil {
		writeError(w, r, err)
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
	user := actor(r)
	use, err := s.store.ReserveAIUse(r.Context(), user.ID, aiUseVit, maxVitADay)
	if err != nil {
		writeError(w, r, err)
		return
	}
	if use == uuid.Nil {
		writeError(w, r, errVitLimit)
		return
	}
	now := time.Now()
	local := now.In(indiaTime)
	rows, _, err := s.store.Meals(r.Context(), local.AddDate(0, 0, -vitDaysBack).Format("2006-01-02"), local.AddDate(0, 0, 1).Format("2006-01-02"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	meals := make([]vitMeal, 0, len(rows))
	for index := len(rows) - 1; index >= 0; index-- {
		meal := rows[index]
		ate := 0.0
		for _, tick := range meal.Ticks {
			if tick.UserID == user.ID {
				ate = tick.Portion
			}
		}
		meals = append(meals, vitMeal{Day: meal.Day, Slot: meal.Slot, Name: meal.Name, Kcal: meal.Kcal, ProteinG: meal.ProteinG, CarbsG: meal.CarbsG, FatG: meal.FatG, Ate: ate})
	}
	answer, err := s.vision.AskVit(r.Context(), user.Name, now, goal, meals, turns)
	if err != nil {
		log.Printf("[%s] vit failed", middleware.GetReqID(r.Context()))
		writeError(w, r, err)
		return
	}
	reply := map[string]any{"reply": answer.Reply, "dishes": answer.Dishes}
	if err := s.store.FinishAIUse(r.Context(), use); err != nil {
		log.Printf("[%s] vit: answered but not marked used: %v", middleware.GetReqID(r.Context()), err)
	} else if used, err := s.store.AIUsesToday(r.Context(), user.ID, aiUseVit); err != nil {
		log.Printf("[%s] vit: could not count today's messages: %v", middleware.GetReqID(r.Context()), err)
	} else {
		reply["left"] = max(0, maxVitADay-used)
	}
	writeJSON(w, http.StatusOK, reply)
}

// cleanVitTurns checks a conversation the model can take: 1 to maxVitTurns messages, mine and Vit's in turn,
// starting and ending with mine, each 1 to maxVitText characters once trimmed.
// Returns: the trimmed turns, or a 400 naming what is wrong
func cleanVitTurns(raw []VitTurn) ([]VitTurn, error) {
	if len(raw) == 0 || len(raw) > maxVitTurns {
		return nil, badRequest(fmt.Sprintf("messages must hold 1 to %d turns", maxVitTurns))
	}
	turns := make([]VitTurn, 0, len(raw))
	for index, turn := range raw {
		want := "user"
		if index%2 == 1 {
			want = "assistant"
		}
		if turn.Role != want {
			return nil, badRequest("messages must start with mine and take turns with Vit's")
		}
		text := strings.TrimSpace(turn.Text)
		if !textBetween(text, 1, maxVitText) {
			return nil, badRequest(fmt.Sprintf("each message must be 1 to %d characters", maxVitText))
		}
		turns = append(turns, VitTurn{Role: turn.Role, Text: text})
	}
	if turns[len(turns)-1].Role != "user" {
		return nil, badRequest("the last message must be mine")
	}
	return turns, nil
}

// ReserveAIUse takes one of a member's daily model calls of a kind, under a lock so two requests at once cannot
// both take the last one. A reservation counts until FinishAIUse marks it done; one never finished (the model
// failed) stops counting after a minute, which gives the call back.
// Args: userID, kind (aiUseVit or aiUseIdeaAgain), limit (calls a day, India time)
// Returns: the reservation's id, or uuid.Nil when the day's limit is used
func (s *Store) ReserveAIUse(ctx context.Context, userID uuid.UUID, kind string, limit int) (uuid.UUID, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, fmt.Errorf("begin ai use: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtext($1::text || $2::text))", userID, kind); err != nil {
		return uuid.Nil, fmt.Errorf("lock ai use: %w", err)
	}
	var used int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM home_ai_uses WHERE user_id = $1 AND kind = $2 AND created_at >= (date_trunc('day', now() AT TIME ZONE 'Asia/Kolkata') AT TIME ZONE 'Asia/Kolkata') AND (done OR created_at > now() - interval '1 minute')", userID, kind).Scan(&used); err != nil {
		return uuid.Nil, fmt.Errorf("count ai uses: %w", err)
	}
	if used >= limit {
		return uuid.Nil, nil
	}
	var id uuid.UUID
	if err := tx.QueryRow(ctx, "INSERT INTO home_ai_uses (user_id, kind) VALUES ($1, $2) RETURNING id", userID, kind).Scan(&id); err != nil {
		return uuid.Nil, fmt.Errorf("save ai use: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return uuid.Nil, fmt.Errorf("commit ai use: %w", err)
	}
	return id, nil
}

// FinishAIUse marks a reservation as a call that was answered, so it counts for the rest of the day.
func (s *Store) FinishAIUse(ctx context.Context, id uuid.UUID) error {
	if _, err := s.pool.Exec(ctx, "UPDATE home_ai_uses SET done = true WHERE id = $1", id); err != nil {
		return fmt.Errorf("finish ai use: %w", err)
	}
	return nil
}

// AIUsesToday counts a member's answered calls of a kind since midnight India time.
func (s *Store) AIUsesToday(ctx context.Context, userID uuid.UUID, kind string) (int, error) {
	var used int
	if err := s.pool.QueryRow(ctx, "SELECT count(*) FROM home_ai_uses WHERE user_id = $1 AND kind = $2 AND done AND created_at >= (date_trunc('day', now() AT TIME ZONE 'Asia/Kolkata') AT TIME ZONE 'Asia/Kolkata')", userID, kind).Scan(&used); err != nil {
		return 0, fmt.Errorf("count ai uses: %w", err)
	}
	return used, nil
}
