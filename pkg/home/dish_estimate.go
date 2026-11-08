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

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/go-chi/chi/v5/middleware"
)

const (
	dishEstimatePath = "/v1/dishes/estimate"
	maxDishNameText  = 80
)

var errEstimateUnavailable = apiError{status: http.StatusServiceUnavailable, Code: "estimate_unavailable", Message: "dish estimates are not set up on this server"}
var errEstimateFailed = apiError{status: http.StatusBadGateway, Code: "estimate_failed", Message: "could not estimate that dish, fill the numbers by hand"}

const dishPrompt = `You are estimating nutrition for a pure-vegetarian Indian home kitchen in Pune. The dish is: %q.
Give calories, protein, carbs and fat for ONE normal home serving for one adult (the plate as it is usually eaten: a sabzi comes with 2 chapati and a small salad, a rice dish is one full plate, a snack is one typical portion).
Then list the ingredients needed to cook the dish for TWO people, each with a short plain name (no brand) and an amount the kitchen can count: grams or kilograms for solids ("200 g", "1 kg"), millilitres or litres for liquids ("250 ml"), pieces for countable things ("2 pcs"). Skip spices, salt, oil and other pantry staples. At most 12 ingredients. If the name is not food, answer with zero calories and no ingredients.`

var dishSchema = dishSchemaWith()

// dishSchemaWith builds the JSON output schema a dish answer must follow: the per-plate numbers and the ingredient
// rows, plus any extra string fields the caller names (the photo reader adds the dish name).
func dishSchemaWith(extra ...string) map[string]any {
	properties := map[string]any{
		"kcal":     map[string]any{"type": "integer"},
		"proteinG": map[string]any{"type": "integer"},
		"carbsG":   map[string]any{"type": "integer"},
		"fatG":     map[string]any{"type": "integer"},
		"ingredients": map[string]any{
			"type": "array",
			"items": map[string]any{
				"type":                 "object",
				"properties":           map[string]any{"name": map[string]any{"type": "string"}, "qty": map[string]any{"type": "string"}},
				"required":             []string{"name", "qty"},
				"additionalProperties": false,
			},
		},
	}
	required := []string{"kcal", "proteinG", "carbsG", "fatG", "ingredients"}
	for _, field := range extra {
		properties[field] = map[string]any{"type": "string"}
		required = append(required, field)
	}
	return map[string]any{"type": "object", "properties": properties, "required": required, "additionalProperties": false}
}

// DishEstimate is what the Add dish sheet fills in for a name the library has not seen: per-person nutrition and
// ingredients for two, the same shape a library dish has.
type DishEstimate struct {
	Kcal        int          `json:"kcal"`
	ProteinG    int          `json:"proteinG"`
	CarbsG      int          `json:"carbsG"`
	FatG        int          `json:"fatG"`
	Serves      int          `json:"serves"`
	Ingredients []Ingredient `json:"ingredients"`
}

// EstimateDish asks the model for one dish's nutrition and recipe, then runs the answer through the same checks a
// posted meal gets, so nothing the app cannot save or the inventory cannot count comes back.
// Returns: the estimate with serves 2; errEstimateFailed when the model errors, refuses, or answers out of range
func (v *Vision) EstimateDish(ctx context.Context, name string) (DishEstimate, error) {
	started := time.Now()
	response, err := v.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:        visionModel,
		MaxTokens:    1200,
		OutputConfig: anthropic.OutputConfigParam{Effort: anthropic.OutputConfigEffortLow, Format: anthropic.JSONOutputFormatParam{Schema: dishSchema}},
		Messages:     []anthropic.MessageParam{anthropic.NewUserMessage(anthropic.NewTextBlock(fmt.Sprintf(dishPrompt, name)))},
	})
	if err != nil {
		log.Printf("dish estimate: model call failed after %s: %v", time.Since(started).Round(time.Millisecond), err)
		return DishEstimate{}, errEstimateFailed
	}
	if response.StopReason == anthropic.StopReasonRefusal {
		log.Printf("dish estimate: model declined")
		return DishEstimate{}, errEstimateFailed
	}
	estimate, _, err := dishFromReply(replyText(response), name)
	if err != nil {
		log.Printf("dish estimate: %v", err)
		return DishEstimate{}, errEstimateFailed
	}
	log.Printf("dish estimate: ok in %s, %d ingredients, %d in / %d out tokens", time.Since(started).Round(time.Millisecond), len(estimate.Ingredients), response.Usage.InputTokens, response.Usage.OutputTokens)
	return estimate, nil
}

// replyText joins the text blocks of a model answer; with a JSON output format that is the whole answer.
func replyText(response *anthropic.Message) string {
	var text strings.Builder
	for _, block := range response.Content {
		if textBlock, ok := block.AsAny().(anthropic.TextBlock); ok {
			text.WriteString(textBlock.Text)
		}
	}
	return text.String()
}

// dishFromReply turns a model answer into the estimate the app saves, through the same checks a posted meal gets,
// so nothing the app cannot save or the inventory cannot count comes back.
// Args: text (the model's JSON), name (the dish to validate under; empty takes the name the reply carries)
// Returns: the estimate with serves 2 and the dish name, or why the reply is unusable
func dishFromReply(text, name string) (DishEstimate, string, error) {
	var parsed struct {
		Name                         string
		Kcal, ProteinG, CarbsG, FatG int
		Ingredients                  []ingredientBody
	}
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		return DishEstimate{}, "", fmt.Errorf("reply was not the expected shape: %w", err)
	}
	if name == "" {
		name = displayName(parsed.Name)
		if !textBetween(name, 1, maxDishNameText) {
			return DishEstimate{}, "", errors.New("reply named no dish")
		}
	}
	ingredients := make([]ingredientBody, 0, len(parsed.Ingredients))
	for _, raw := range parsed.Ingredients {
		ingredient := ingredientBody{Name: displayName(raw.Name), Qty: strings.TrimSpace(raw.Qty)}
		if _, ok := ParseQuantity(ingredient.Qty); !ok || !textBetween(ingredient.Name, 1, maxIngredientName) || !textBetween(ingredient.Qty, 1, maxIngredientQty) {
			continue
		}
		ingredients = append(ingredients, ingredient)
		if len(ingredients) == maxIngredients {
			break
		}
	}
	body := mealBody{Day: "2000-01-01", Slot: "lunch", Name: name, Kcal: parsed.Kcal, ProteinG: parsed.ProteinG, CarbsG: parsed.CarbsG, FatG: parsed.FatG, Serves: 2, Ingredients: ingredients}
	meal, err := body.validate()
	if err != nil {
		return DishEstimate{}, "", fmt.Errorf("reply out of range: %w", err)
	}
	return DishEstimate{Kcal: meal.Kcal, ProteinG: meal.ProteinG, CarbsG: meal.CarbsG, FatG: meal.FatG, Serves: meal.Serves, Ingredients: meal.Ingredients}, name, nil
}

type estimateBody struct {
	Name string `json:"name"`
}

// estimateDish answers the Add dish sheet for a name the library does not know: POST /v1/dishes/estimate {name}.
// Handles: no key on the server (503), an empty or long name (400), a model failure (502)
func (s *Server) estimateDish(w http.ResponseWriter, r *http.Request) {
	if s.vision == nil {
		writeError(w, r, errEstimateUnavailable)
		return
	}
	var body estimateBody
	if err := decode(r, &body); err != nil {
		writeError(w, r, err)
		return
	}
	name := strings.Join(strings.Fields(body.Name), " ")
	if !textBetween(name, 1, maxDishNameText) {
		writeError(w, r, badRequest(fmt.Sprintf("name must be 1 to %d characters", maxDishNameText)))
		return
	}
	estimate, err := s.vision.EstimateDish(r.Context(), name)
	if err != nil {
		log.Printf("[%s] dish estimate failed", middleware.GetReqID(r.Context()))
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, estimate)
}
