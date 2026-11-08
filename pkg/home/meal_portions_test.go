package home

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

// twoPhones is one home with two members signed in, as two phones would be.
func twoPhones(t *testing.T) (server *httptest.Server, rahul, nikita string, rahulID, nikitaID string) {
	t.Helper()
	store := testStore(t)
	user1, pass1 := testUser(t, store)
	user2, pass2 := testUser(t, store)
	server = httptest.NewServer(NewServer(store, Config{AllowLocalhost: true}))
	t.Cleanup(server.Close)
	rahul = signIn(t, server, user1, pass1)
	nikita = signIn(t, server, user2, pass2)
	_, me1 := call(t, server, http.MethodGet, "/v1/me", rahul, nil)
	_, me2 := call(t, server, http.MethodGet, "/v1/me", nikita, nil)
	return server, rahul, nikita, me1["id"].(string), me2["id"].(string)
}

func ticksOf(meal map[string]any) map[string]float64 {
	out := map[string]float64{}
	for _, raw := range meal["ticks"].([]any) {
		tick := raw.(map[string]any)
		out[tick["userId"].(string)] = tick["portion"].(float64)
	}
	return out
}

func TestAddingADishSaysWhoAteAndHowMuch(t *testing.T) {
	server, rahul, nikita, rahulID, nikitaID := twoPhones(t)
	day := testDays(1)[0]
	body := mealRow("dinner", "Puran Poli", 743)
	body["day"] = day
	body["eaters"] = []any{map[string]any{}, map[string]any{"userId": nikitaID, "portion": 0.5}}
	status, saved := call(t, server, http.MethodPost, "/v1/meals", rahul, body)
	if status != http.StatusCreated {
		t.Fatalf("add with eaters: %d %v", status, saved)
	}
	id := saved["id"].(string)
	t.Cleanup(func() { call(t, server, http.MethodDelete, "/v1/meals/"+id, rahul, nil) })
	if got := ticksOf(saved); len(got) != 2 || got[rahulID] != 1 || got[nikitaID] != 0.5 {
		t.Fatalf("eaters should land as ticks, me at one plate and Nikita at half: %v", got)
	}
	if ticked := saved["tickedBy"].([]any); len(ticked) != 2 {
		t.Fatalf("older builds read tickedBy, which should list both: %v", ticked)
	}

	if status, _ := call(t, server, http.MethodPut, "/v1/meals/"+id+"/tick", nikita, map[string]any{"portion": 1.5}); status != http.StatusNoContent {
		t.Fatalf("Nikita changes her own plate: %d", status)
	}
	if got := ticksOf(mealsOn(t, server, rahul, day, day)[0]); got[nikitaID] != 1.5 || got[rahulID] != 1 {
		t.Fatalf("her portion should be 1.5 and mine untouched: %v", got)
	}

	if status, _ := call(t, server, http.MethodPut, "/v1/meals/"+id+"/tick", rahul, map[string]any{"userId": nikitaID, "portion": 2}); status != http.StatusNoContent {
		t.Fatalf("my phone ticks for Nikita: %d", status)
	}
	if got := ticksOf(mealsOn(t, server, rahul, day, day)[0]); got[nikitaID] != 2 {
		t.Fatalf("her portion should now be 2: %v", got)
	}

	if status, _ := call(t, server, http.MethodDelete, "/v1/meals/"+id+"/tick?userId="+nikitaID, rahul, nil); status != http.StatusNoContent {
		t.Fatalf("my phone clears Nikita's tick: %d", status)
	}
	if got := ticksOf(mealsOn(t, server, rahul, day, day)[0]); len(got) != 1 || got[rahulID] != 1 {
		t.Fatalf("only my tick should remain: %v", got)
	}

	if status, _ := call(t, server, http.MethodPut, "/v1/meals/"+id+"/tick", nikita, nil); status != http.StatusNoContent {
		t.Fatalf("a tick with no body, as the old app sends it: %d", status)
	}
	if got := ticksOf(mealsOn(t, server, rahul, day, day)[0]); got[nikitaID] != 1 {
		t.Fatalf("no body means one plate: %v", got)
	}
}

func TestTicksRefuseStrangersAndOddPlates(t *testing.T) {
	server, rahul, _, _, nikitaID := twoPhones(t)
	day := testDays(1)[0]
	body := mealRow("lunch", "Khichdi", 500)
	body["day"] = day
	status, saved := call(t, server, http.MethodPost, "/v1/meals", rahul, body)
	if status != http.StatusCreated {
		t.Fatalf("add: %d %v", status, saved)
	}
	id := saved["id"].(string)
	t.Cleanup(func() { call(t, server, http.MethodDelete, "/v1/meals/"+id, rahul, nil) })
	if got := ticksOf(saved); len(got) != 0 {
		t.Fatalf("no eaters means no ticks: %v", got)
	}

	cases := []struct {
		name string
		body map[string]any
	}{
		{"a plate size the app does not offer", map[string]any{"portion": 0.75}},
		{"a negative plate", map[string]any{"portion": -1}},
		{"a person from another home", map[string]any{"userId": uuid.NewString()}},
		{"a field the route does not know", map[string]any{"ate": true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if status, _ := call(t, server, http.MethodPut, "/v1/meals/"+id+"/tick", rahul, tc.body); status != http.StatusBadRequest {
				t.Fatalf("want 400, got %d", status)
			}
		})
	}
	if status, _ := call(t, server, http.MethodDelete, "/v1/meals/"+id+"/tick?userId=not-a-uuid", rahul, nil); status != http.StatusBadRequest {
		t.Fatalf("a malformed userId on clear: want 400, got %d", status)
	}
	if got := ticksOf(mealsOn(t, server, rahul, day, day)[0]); len(got) != 0 {
		t.Fatalf("refused ticks must leave nothing behind: %v", got)
	}

	addCases := []struct {
		name   string
		eaters []any
	}{
		{"the same person twice", []any{map[string]any{"userId": nikitaID}, map[string]any{"userId": nikitaID, "portion": 2}}},
		{"an eater at a plate size the app does not offer", []any{map[string]any{"portion": 4}}},
		{"an eater from another home", []any{map[string]any{"userId": uuid.NewString()}}},
	}
	before := len(mealsOn(t, server, rahul, day, day))
	for _, tc := range addCases {
		t.Run("adding with "+tc.name, func(t *testing.T) {
			body := mealRow("snack", "Chivda", 150)
			body["day"] = day
			body["eaters"] = tc.eaters
			if status, _ := call(t, server, http.MethodPost, "/v1/meals", rahul, body); status != http.StatusBadRequest {
				t.Fatalf("want 400, got %d", status)
			}
		})
	}
	if after := len(mealsOn(t, server, rahul, day, day)); after != before {
		t.Fatalf("a refused add must not leave a meal behind: %d → %d", before, after)
	}
}
