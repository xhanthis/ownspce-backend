package home

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/google/uuid"
)

// countingModel answers every Messages call with reply and counts the calls, so a test can tell a cached answer
// from a fresh one.
func countingModel(t *testing.T, reply string) (*Vision, *atomic.Int32, *string) {
	t.Helper()
	var calls atomic.Int32
	var prompt string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var request struct {
			Messages []struct {
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&request)
		if len(request.Messages) > 0 && len(request.Messages[0].Content) > 0 {
			prompt = request.Messages[0].Content[0].Text
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "msg_test", "type": "message", "role": "assistant", "model": visionModel,
			"content":     []map[string]any{{"type": "text", "text": reply}},
			"stop_reason": "end_turn",
			"usage":       map[string]any{"input_tokens": 100, "output_tokens": 50},
		})
	}))
	t.Cleanup(server.Close)
	return &Vision{client: anthropic.NewClient(option.WithAPIKey("test-token-not-real"), option.WithBaseURL(server.URL), option.WithMaxRetries(0))}, &calls, &prompt
}

func idea(target, value, name string, kcal int) string {
	return fmt.Sprintf(`{%q:%q,"name":%q,"why":"  lighter,   same comfort ","kcal":%d,"proteinG":18,"carbsG":40,"fatG":9,"ingredients":[{"name":"moong dal","qty":"200 g"},{"name":"Ginger","qty":"a little"}]}`, target, value, name, kcal)
}

func TestSuggestMealsKeepsOnlyIdeasThatFitTheDay(t *testing.T) {
	biryani, dal, eaten := uuid.New(), uuid.New(), uuid.New()
	reply := `{"fills":[` + strings.Join([]string{
		idea("slot", "breakfast", "Moong chilla", 280),
		idea("slot", "breakfast", "Poha", 300),
		idea("slot", "lunch", "Dal rice", 500),
		idea("slot", "dinner", "Thali", 9000),
	}, ",") + `],"swaps":[` + strings.Join([]string{
		idea("mealId", biryani.String(), "Veg pulao with raita", 420),
		idea("mealId", biryani.String(), "Jeera rice", 380),
		idea("mealId", eaten.String(), "Khichdi", 350),
		idea("mealId", dal.String(), "dal RICE", 450),
		idea("mealId", "not-an-id", "Upma", 300),
	}, ",") + `]}`
	vision, _, prompt := countingModel(t, reply)
	input := suggestInput{Day: "2100-01-02", Dishes: []suggestDish{{ID: biryani, Slot: "lunch", Name: "Veg Biryani", Kcal: 540, ProteinG: 12}}, Goal: map[string]any{"goalWeightKg": 70.0}, Favourites: []string{"Pav Bhaji"}}

	ideas, err := vision.SuggestMeals(context.Background(), input, []string{"breakfast", "dinner"}, []uuid.UUID{biryani, dal})
	if err != nil {
		t.Fatal(err)
	}
	usable := ideas.keepUsable([]string{"breakfast", "dinner"}, map[uuid.UUID]string{biryani: "Veg Biryani", dal: "Dal rice"})

	if len(usable.Fills) != 1 || usable.Fills[0].Slot != "breakfast" || usable.Fills[0].Name != "Moong chilla" {
		t.Fatalf("one breakfast, the first; a filled lunch and a 9000 kcal dinner are dropped: %+v", usable.Fills)
	}
	fill := usable.Fills[0]
	if fill.Why != "lighter, same comfort" || fill.Serves != 2 || len(fill.Ingredients) != 1 || fill.MealID != nil {
		t.Fatalf("fill checked like an estimate: %+v", fill)
	}
	if len(usable.Swaps) != 1 || *usable.Swaps[0].MealID != biryani || usable.Swaps[0].Name != "Veg pulao with raita" || usable.Swaps[0].Slot != "" {
		t.Fatalf("one swap for the biryani; eaten, same-name and bad ids are dropped: %+v", usable.Swaps)
	}
	for _, want := range []string{`["breakfast","dinner"]`, biryani.String(), `"goalWeightKg":70`, `["Pav Bhaji"]`, "2100-01-02"} {
		if !strings.Contains(*prompt, want) {
			t.Fatalf("prompt is missing %s: %s", want, *prompt)
		}
	}
}

func TestSuggestMealsFailsOnARefusalOrJunk(t *testing.T) {
	for name, tc := range map[string]struct{ reply, stop string }{
		"refusal":  {`{}`, "refusal"},
		"not json": {`here are some ideas`, "end_turn"},
	} {
		t.Run(name, func(t *testing.T) {
			vision, _ := fakeModel(t, tc.reply, tc.stop)
			if _, err := vision.SuggestMeals(context.Background(), suggestInput{Day: "2100-01-02"}, []string{"lunch"}, nil); err != errSuggestFailed {
				t.Fatalf("want errSuggestFailed, got %v", err)
			}
		})
	}
}

func TestSuggestRouteAsksOnceServesTheCacheAndDropsEatenDishes(t *testing.T) {
	store := testStore(t)
	username, password := testUser(t, store)
	plain := httptest.NewServer(newServer(store, Config{AllowLocalhost: true}, nil))
	t.Cleanup(plain.Close)
	token := signIn(t, plain, username, password)
	day := testDays(1)[0]
	menu := map[string]any{"days": []any{map[string]any{"day": day, "meals": []any{mealRow("lunch", "Veg Biryani", 540)}}}}
	if status, body := call(t, plain, http.MethodPost, "/v1/meals/import", token, menu); status != http.StatusOK {
		t.Fatalf("import: %d %v", status, body)
	}
	biryani := mealsOn(t, plain, token, day, day)[0]["id"].(string)
	ask := map[string]any{"day": day, "goal": map[string]any{"goalWeightKg": 70, "proteinTargetG": 117}, "favourites": []string{"Pav Bhaji"}}

	if status, body := call(t, plain, http.MethodPost, "/v1/meals/suggest", token, ask); status != http.StatusServiceUnavailable {
		t.Fatalf("without a key: %d %v", status, body)
	}

	reply := `{"fills":[` + idea("slot", "breakfast", "Moong chilla", 280) + `,` + idea("slot", "dinner", "Palak khichdi", 420) + `],"swaps":[` + idea("mealId", biryani, "Veg pulao with raita", 420) + `]}`
	vision, calls, _ := countingModel(t, reply)
	server := httptest.NewServer(newServer(store, Config{AllowLocalhost: true}, vision))
	t.Cleanup(server.Close)

	status, first := call(t, server, http.MethodPost, "/v1/meals/suggest", token, ask)
	if status != http.StatusOK || first["fresh"] != true || len(first["fills"].([]any)) != 2 || len(first["swaps"].([]any)) != 1 {
		t.Fatalf("first ask: %d %v", status, first)
	}
	swap := first["swaps"].([]any)[0].(map[string]any)
	if swap["mealId"] != biryani || swap["name"] != "Veg pulao with raita" || swap["kcal"].(float64) != 420 {
		t.Fatalf("swap: %v", swap)
	}

	status, again := call(t, server, http.MethodPost, "/v1/meals/suggest", token, ask)
	if status != http.StatusOK || again["fresh"] != false || len(again["swaps"].([]any)) != 1 || calls.Load() != 1 {
		t.Fatalf("the same ask comes from the cache: %d %v, %d calls", status, again, calls.Load())
	}

	if status, _ := call(t, server, http.MethodPut, "/v1/meals/"+biryani+"/tick", token, nil); status != http.StatusNoContent {
		t.Fatalf("tick: %d", status)
	}
	status, eaten := call(t, server, http.MethodPost, "/v1/meals/suggest", token, ask)
	if status != http.StatusOK || len(eaten["swaps"].([]any)) != 0 || len(eaten["fills"].([]any)) != 2 || calls.Load() != 1 {
		t.Fatalf("a tick needs no new ask, and an eaten dish is not swapped: %d %v, %d calls", status, eaten, calls.Load())
	}

	past := map[string]any{"day": "2001-01-01"}
	if status, body := call(t, server, http.MethodPost, "/v1/meals/suggest", token, past); status != http.StatusOK || len(body["fills"].([]any)) != 0 || calls.Load() != 1 {
		t.Fatalf("a past day gets no ideas and no model call: %d %v", status, body)
	}
	for _, bad := range []map[string]any{{"day": "tomorrow"}, {"day": day, "goal": map[string]any{"nested": map[string]any{"x": 1}}}} {
		if status, body := call(t, server, http.MethodPost, "/v1/meals/suggest", token, bad); status != http.StatusBadRequest {
			t.Fatalf("bad ask %v: %d %v", bad, status, body)
		}
	}
	if status, _ := call(t, server, http.MethodPost, "/v1/meals/suggest", "", ask); status != http.StatusUnauthorized {
		t.Fatalf("no token: %d", status)
	}
}
