package home

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/google/uuid"
)

// modelLog keeps the text of every request a fake model got: the system prompt and each message, one entry per call.
type modelLog struct {
	mu       sync.Mutex
	requests []string
}

func (l *modelLog) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.requests...)
}

// countingModel answers every Messages call with reply and counts the calls, so a test can tell a cached answer
// from a fresh one. Calls may come at once; each one's text lands in the log.
func countingModel(t *testing.T, reply string) (*Vision, *atomic.Int32, *modelLog) {
	t.Helper()
	var calls atomic.Int32
	seen := &modelLog{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var request struct {
			System []struct {
				Text string `json:"text"`
			} `json:"system"`
			Messages []struct {
				Role    string `json:"role"`
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&request)
		var text strings.Builder
		for _, block := range request.System {
			text.WriteString("system: " + block.Text + "\n")
		}
		for _, message := range request.Messages {
			for _, block := range message.Content {
				text.WriteString(message.Role + ": " + block.Text + "\n")
			}
		}
		seen.mu.Lock()
		seen.requests = append(seen.requests, text.String())
		seen.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "msg_test", "type": "message", "role": "assistant", "model": visionModel,
			"content":     []map[string]any{{"type": "text", "text": reply}},
			"stop_reason": "end_turn",
			"usage":       map[string]any{"input_tokens": 100, "output_tokens": 50},
		})
	}))
	t.Cleanup(server.Close)
	return &Vision{client: anthropic.NewClient(option.WithAPIKey("test-token-not-real"), option.WithBaseURL(server.URL), option.WithMaxRetries(0))}, &calls, seen
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
	vision, calls, seen := countingModel(t, reply)
	input := suggestInput{Day: "2100-01-02", Dishes: []suggestDish{{ID: biryani, Slot: "lunch", Name: "Veg Biryani", Kcal: 540, ProteinG: 12}}, Goal: map[string]any{"goalWeightKg": 70.0}, Favourites: []string{"Pav Bhaji"}}

	ideas, err := vision.SuggestMeals(context.Background(), input, []string{"breakfast", "dinner"}, []uuid.UUID{biryani, dal}, ideasPerSlot, nil)
	if err != nil {
		t.Fatal(err)
	}
	usable := ideas.keepUsable([]string{"breakfast", "dinner"}, map[uuid.UUID]string{biryani: "Veg Biryani", dal: "Dal rice"})

	if len(usable.Fills) != 1 || usable.Fills[0].Name != "Moong chilla" || usable.Fills[0].Slot != "breakfast" {
		t.Fatalf("one breakfast, the first; a filled lunch and a 9000 kcal dinner are left out: %+v", usable.Fills)
	}
	if calls.Load() != 3 {
		t.Fatalf("one call per empty slot and one for the swaps, got %d", calls.Load())
	}
	fill := usable.Fills[0]
	if fill.Why != "lighter, same comfort" || fill.Serves != 2 || len(fill.Ingredients) != 1 || fill.MealID != nil {
		t.Fatalf("fill checked like an estimate: %+v", fill)
	}
	if len(usable.Swaps) != 1 || *usable.Swaps[0].MealID != biryani || usable.Swaps[0].Name != "Veg pulao with raita" || usable.Swaps[0].Slot != "" {
		t.Fatalf("one swap for the biryani; eaten, same-name and bad ids are dropped: %+v", usable.Swaps)
	}
	prompts := strings.Join(seen.all(), "\n---\n")
	for _, want := range []string{`slots with 1 real home dish(es) each; never leave one of them out: ["breakfast"]`, `out: ["dinner"]`, `out: []`, `Ids: ["` + biryani.String(), `"goalWeightKg":70`, `["Pav Bhaji"]`, "2100-01-02", "never suggest any of these: []", "by the goal date (goalBy) while building muscle"} {
		if !strings.Contains(prompts, want) {
			t.Fatalf("prompts are missing %s: %s", want, prompts)
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
			if _, err := vision.SuggestMeals(context.Background(), suggestInput{Day: "2100-01-02"}, []string{"lunch"}, nil, ideasPerSlot, nil); err != errSuggestFailed {
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
	ask := map[string]any{"day": day, "goal": map[string]any{"goalWeightKg": 70, "proteinTargetG": 117, "goalBy": "2027-04-05"}, "favourites": []string{"Pav Bhaji"}, "week": []string{"  Rajma   chawal ", ""}}

	if status, body := call(t, plain, http.MethodPost, "/v1/meals/suggest", token, ask); status != http.StatusServiceUnavailable {
		t.Fatalf("without a key: %d %v", status, body)
	}

	reply := `{"fills":[` + idea("slot", "breakfast", "Moong chilla", 280) + `,` + idea("slot", "dinner", "Palak khichdi", 420) + `],"swaps":[` + idea("mealId", biryani, "Veg pulao with raita", 420) + `]}`
	vision, calls, seen := countingModel(t, reply)
	server := httptest.NewServer(newServer(store, Config{AllowLocalhost: true}, vision))
	t.Cleanup(server.Close)

	status, first := call(t, server, http.MethodPost, "/v1/meals/suggest", token, ask)
	if status != http.StatusOK || first["fresh"] != true || first["pending"] != true || len(first["fills"].([]any)) != 2 || len(first["swaps"].([]any)) != 1 || calls.Load() != 4 {
		t.Fatalf("first ask: one call each for breakfast, snack and dinner plus the swaps; snack comes back empty: %d %v, %d calls", status, first, calls.Load())
	}
	if prompt := strings.Join(seen.all(), "\n"); !strings.Contains(prompt, `never suggest any of these: ["Rajma chawal"]`) || !strings.Contains(prompt, `"goalBy":"2027-04-05"`) {
		t.Fatalf("the week's dishes and the goal date reach the model: %s", prompt)
	}
	swap := first["swaps"].([]any)[0].(map[string]any)
	if swap["mealId"] != biryani || swap["name"] != "Veg pulao with raita" || swap["kcal"].(float64) != 420 {
		t.Fatalf("swap: %v", swap)
	}

	for try, wantPending := range []bool{true, false} {
		before := len(seen.all())
		status, again := call(t, server, http.MethodPost, "/v1/meals/suggest", token, ask)
		if status != http.StatusOK || again["fresh"] != true || again["pending"] != wantPending || len(again["fills"].([]any)) != 2 || len(again["swaps"].([]any)) != 1 || calls.Load() != int32(5+try) {
			t.Fatalf("try %d asks the skipped snack again, alone: %d %v, %d calls", try+2, status, again, calls.Load())
		}
		if prompt := seen.all()[before]; !strings.Contains(prompt, `out: ["snack"]`) || !strings.Contains(prompt, `Ids: []`) {
			t.Fatalf("only the snack is asked again, with no swaps: %s", prompt)
		}
	}
	status, again := call(t, server, http.MethodPost, "/v1/meals/suggest", token, ask)
	if status != http.StatusOK || again["fresh"] != false || again["pending"] != false || len(again["swaps"].([]any)) != 1 || calls.Load() != 6 {
		t.Fatalf("after maxSuggestTries the kept answer is served with no call: %d %v, %d calls", status, again, calls.Load())
	}

	if status, _ := call(t, server, http.MethodPut, "/v1/meals/"+biryani+"/tick", token, nil); status != http.StatusNoContent {
		t.Fatalf("tick: %d", status)
	}
	status, eaten := call(t, server, http.MethodPost, "/v1/meals/suggest", token, ask)
	if status != http.StatusOK || len(eaten["swaps"].([]any)) != 0 || len(eaten["fills"].([]any)) != 2 || calls.Load() != 6 {
		t.Fatalf("a tick needs no new ask, and an eaten dish is not swapped: %d %v, %d calls", status, eaten, calls.Load())
	}

	if status, _ := call(t, server, http.MethodDelete, "/v1/meals/"+biryani, token, nil); status >= 300 {
		t.Fatalf("remove lunch: %d", status)
	}
	before := len(seen.all())
	if status, opened := call(t, server, http.MethodPost, "/v1/meals/suggest", token, ask); status != http.StatusOK || opened["fresh"] != true || calls.Load() != 7 {
		t.Fatalf("a slot that opens after the snack's tries are spent is still asked: %d %v, %d calls", status, opened, calls.Load())
	}
	if prompt := seen.all()[before]; !strings.Contains(prompt, `out: ["lunch"]`) {
		t.Fatalf("only lunch is asked; the snack has no tries left: %s", prompt)
	}

	past := map[string]any{"day": "2001-01-01"}
	if status, body := call(t, server, http.MethodPost, "/v1/meals/suggest", token, past); status != http.StatusOK || len(body["fills"].([]any)) != 0 || calls.Load() != 7 {
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

func TestSuggestRouteKeepsADaysIdeasWhenItsPlanChanges(t *testing.T) {
	store := testStore(t)
	username, password := testUser(t, store)
	reply := `{"fills":[` + idea("slot", "breakfast", "Moong chilla", 280) + `,` + idea("slot", "lunch", "Dal rice", 480) + `,` + idea("slot", "snack", "Masala chana", 220) + `,` + idea("slot", "dinner", "Palak khichdi", 420) + `],"swaps":[]}`
	vision, calls, seen := countingModel(t, reply)
	server := httptest.NewServer(newServer(store, Config{AllowLocalhost: true}, vision))
	t.Cleanup(server.Close)
	token := signIn(t, server, username, password)
	day := testDays(1)[0]
	menu := map[string]any{"days": []any{map[string]any{"day": day, "meals": []any{mealRow("lunch", "Veg Biryani", 540)}}}}
	if status, body := call(t, server, http.MethodPost, "/v1/meals/import", token, menu); status != http.StatusOK {
		t.Fatalf("import: %d %v", status, body)
	}
	biryani := mealsOn(t, server, token, day, day)[0]["id"].(string)
	ask := map[string]any{"day": day, "goal": map[string]any{"goalWeightKg": 70}}
	names := func(body map[string]any) []string {
		out := []string{}
		for _, fill := range body["fills"].([]any) {
			out = append(out, fill.(map[string]any)["name"].(string))
		}
		return out
	}

	if status, first := call(t, server, http.MethodPost, "/v1/meals/suggest", token, ask); status != http.StatusOK || strings.Join(names(first), ",") != "Moong chilla,Masala chana,Palak khichdi" || first["pending"] != false || calls.Load() != 4 {
		t.Fatalf("first ask fills breakfast, snack and dinner (late night is never asked): %d %v, %d calls", status, first, calls.Load())
	}

	breakfast := mealRow("breakfast", "Upma", 300)
	breakfast["day"] = day
	status, added := call(t, server, http.MethodPost, "/v1/meals", token, breakfast)
	if status != http.StatusCreated {
		t.Fatalf("add breakfast: %d %v", status, added)
	}
	if status, kept := call(t, server, http.MethodPost, "/v1/meals/suggest", token, ask); status != http.StatusOK || kept["fresh"] != false || strings.Join(names(kept), ",") != "Masala chana,Palak khichdi" || calls.Load() != 4 {
		t.Fatalf("a dish added to the plan asks nothing new and its slot's ideas drop out: %d %v, %d calls", status, kept, calls.Load())
	}

	if status, _ := call(t, server, http.MethodDelete, "/v1/meals/"+biryani, token, nil); status >= 300 {
		t.Fatalf("remove lunch: %d", status)
	}
	before := len(seen.all())
	if status, opened := call(t, server, http.MethodPost, "/v1/meals/suggest", token, ask); status != http.StatusOK || opened["fresh"] != true || strings.Join(names(opened), ",") != "Masala chana,Palak khichdi,Dal rice" || calls.Load() != 5 {
		t.Fatalf("a slot never asked about costs one call for that slot alone: %d %v, %d calls", status, opened, calls.Load())
	}
	if prompt := seen.all()[before]; !strings.Contains(prompt, `out: ["lunch"]`) || !strings.Contains(prompt, `Ids: []`) {
		t.Fatalf("only lunch is asked, with no swaps: %s", prompt)
	}

	if status, _ := call(t, server, http.MethodDelete, "/v1/meals/"+added["id"].(string), token, nil); status >= 300 {
		t.Fatalf("remove breakfast: %d", status)
	}
	if status, back := call(t, server, http.MethodPost, "/v1/meals/suggest", token, ask); status != http.StatusOK || back["fresh"] != false || strings.Join(names(back), ",") != "Moong chilla,Masala chana,Palak khichdi,Dal rice" || calls.Load() != 5 {
		t.Fatalf("a slot that opens again gets its kept ideas back with no call: %d %v, %d calls", status, back, calls.Load())
	}
}

func TestSuggestAgainSwapsOneIdeaInPlaceAndKeepsIt(t *testing.T) {
	store := testStore(t)
	username, password := testUser(t, store)
	first, _, _ := countingModel(t, `{"fills":[`+idea("slot", "breakfast", "Moong chilla", 280)+`,`+idea("slot", "lunch", "Dal rice", 480)+`,`+idea("slot", "snack", "Masala chana", 220)+`,`+idea("slot", "dinner", "Palak khichdi", 420)+`],"swaps":[]}`)
	server := httptest.NewServer(newServer(store, Config{AllowLocalhost: true}, first))
	t.Cleanup(server.Close)
	token := signIn(t, server, username, password)
	user, err := store.UserByUsername(context.Background(), username)
	if err != nil {
		t.Fatal(err)
	}
	day := testDays(1)[0]
	ask := map[string]any{"day": day, "goal": map[string]any{"proteinTargetG": 117}}
	if status, body := call(t, server, http.MethodPost, "/v1/meals/suggest", token, ask); status != http.StatusOK || len(body["fills"].([]any)) != 4 {
		t.Fatalf("first ask: %d %v", status, body)
	}
	again := func(server *httptest.Server, slot, name string) (int, map[string]any) {
		return call(t, server, http.MethodPost, "/v1/meals/suggest/again", token, map[string]any{"day": day, "goal": ask["goal"], "slot": slot, "name": name, "week": []string{"Poha"}})
	}

	if status, body := again(server, "breakfast", "Moong chilla"); status != http.StatusBadGateway {
		t.Fatalf("an answer that only repeats what is shown is a failure: %d %v", status, body)
	}
	if used, _ := store.AIUsesToday(context.Background(), user.ID, aiUseIdeaAgain); used != 0 {
		t.Fatalf("a failed ask is not used up: %d", used)
	}

	fresh, calls, seen := countingModel(t, `{"fills":[`+idea("slot", "breakfast", "Moong chilla", 300)+`,`+idea("slot", "breakfast", "Besan chilla", 260)+`],"swaps":[]}`)
	swapper := httptest.NewServer(newServer(store, Config{AllowLocalhost: true}, fresh))
	t.Cleanup(swapper.Close)
	status, body := again(swapper, "breakfast", "moong CHILLA")
	fills := body["fills"].([]any)
	if status != http.StatusOK || calls.Load() != 1 || len(fills) != 4 || fills[0].(map[string]any)["name"] != "Besan chilla" || fills[1].(map[string]any)["name"] != "Dal rice" || fills[3].(map[string]any)["name"] != "Palak khichdi" {
		t.Fatalf("the new dish takes the old one's place and skips the one shown: %d %v", status, body)
	}
	if prompt := seen.all()[0]; !strings.Contains(prompt, `1 real home dish(es) each; never leave one of them out: ["breakfast"]`) || !strings.Contains(prompt, `never suggest any of these: ["Moong chilla","Poha"]`) {
		t.Fatalf("prompt asks for one new breakfast and names what is shown and the week's dishes: %s", prompt)
	}
	if status, kept := call(t, swapper, http.MethodPost, "/v1/meals/suggest", token, ask); status != http.StatusOK || kept["fills"].([]any)[0].(map[string]any)["name"] != "Besan chilla" || calls.Load() != 1 {
		t.Fatalf("the card keeps the new dish from the cache: %d %v", status, kept)
	}

	for name, tc := range map[string]struct {
		slot, idea string
		want       int
	}{
		"an idea no longer shown": {"breakfast", "Moong chilla", http.StatusConflict},
		"a slot it never fills":   {"late", "Kheer", http.StatusConflict},
		"a slot that is not one":  {"brunch", "Poha", http.StatusBadRequest},
		"no idea named":           {"breakfast", "", http.StatusBadRequest},
	} {
		if status, body := again(swapper, tc.slot, tc.idea); status != tc.want {
			t.Fatalf("%s: want %d, got %d %v", name, tc.want, status, body)
		}
	}

	heldByEarlierAsks := 2
	for range maxIdeaAgainADay - heldByEarlierAsks {
		use, err := store.ReserveAIUse(context.Background(), user.ID, aiUseIdeaAgain, maxIdeaAgainADay)
		if err != nil || use == uuid.Nil {
			t.Fatalf("reserve: %v %v", use, err)
		}
		_ = store.FinishAIUse(context.Background(), use)
	}
	before := calls.Load()
	if status, body := again(swapper, "breakfast", "Besan chilla"); status != http.StatusTooManyRequests || body["error"].(map[string]any)["code"] != "idea_limit" || calls.Load() != before {
		t.Fatalf("past the day's cap: %d %v", status, body)
	}
}
