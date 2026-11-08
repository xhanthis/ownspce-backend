package home

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// dishName makes a name no other run shares, so the shared library never collides across runs.
func dishName(base string) string {
	return base + " " + strings.ReplaceAll(uuid.NewString(), "-", "")[:8]
}

func dishesFor(t *testing.T, server *httptest.Server, token, query string) []map[string]any {
	t.Helper()
	status, listed := call(t, server, http.MethodGet, "/v1/dishes?q="+url.QueryEscape(query), token, nil)
	if status != http.StatusOK {
		t.Fatalf("search dishes: %d %v", status, listed)
	}
	out := []map[string]any{}
	for _, raw := range listed["dishes"].([]any) {
		out = append(out, raw.(map[string]any))
	}
	return out
}

func TestAddDishTeachesTheLibraryAndAllowsTwoLunches(t *testing.T) {
	server, username, password := testServer(t)
	token := signIn(t, server, username, password)
	day := testDays(1)[0]
	name := dishName("Curd rice")
	key := strings.ToLower(name)

	first := mealRow("lunch", name, 600)
	first["day"] = day
	first["saveToLibrary"] = false
	status, added := call(t, server, http.MethodPost, "/v1/meals", token, first)
	if status != http.StatusCreated || added["dishId"] == nil || added["sortOrder"].(float64) != 0 {
		t.Fatalf("first add: %d %v", status, added)
	}

	found := dishesFor(t, server, token, key[:9])
	if len(found) == 0 || found[0]["name"] != name || found[0]["kcal"].(float64) != 600 || found[0]["timesUsed"].(float64) != 1 {
		t.Fatalf("library after first add: %v", found)
	}

	second := mealRow("lunch", "  "+strings.ToUpper(name)+"  ", 650)
	second["day"] = day
	second["saveToLibrary"] = false
	status, again := call(t, server, http.MethodPost, "/v1/meals", token, second)
	if status != http.StatusCreated || again["dishId"] != added["dishId"] || again["sortOrder"].(float64) != 1 {
		t.Fatalf("second add should reuse the dish and take the next sort order: %d %v", status, again)
	}
	found = dishesFor(t, server, token, key[:9])
	if found[0]["kcal"].(float64) != 600 || found[0]["timesUsed"].(float64) != 2 {
		t.Fatalf("without saveToLibrary the numbers stay and the count grows: %v", found[0])
	}

	third := mealRow("lunch", name, 700)
	third["day"] = day
	third["saveToLibrary"] = true
	if status, _ := call(t, server, http.MethodPost, "/v1/meals", token, third); status != http.StatusCreated {
		t.Fatalf("third add: %d", status)
	}
	found = dishesFor(t, server, token, key[:9])
	if found[0]["kcal"].(float64) != 700 || found[0]["timesUsed"].(float64) != 3 {
		t.Fatalf("with saveToLibrary the numbers follow: %v", found[0])
	}

	lunches := 0
	for _, meal := range mealsOn(t, server, token, day, day) {
		if meal["slot"] == "lunch" {
			lunches++
		}
	}
	if lunches != 3 {
		t.Fatalf("expected three lunches on %s, got %d", day, lunches)
	}
}

func TestAddDishRefusesAFullSlotAndBadRows(t *testing.T) {
	server, username, password := testServer(t)
	token := signIn(t, server, username, password)
	day := testDays(1)[0]
	for i := 0; i < MaxMealsPerDay; i++ {
		row := mealRow("snack", dishName("Nuts"), 100)
		row["day"] = day
		if status, body := call(t, server, http.MethodPost, "/v1/meals", token, row); status != http.StatusCreated {
			t.Fatalf("add %d: %d %v", i, status, body)
		}
	}
	row := mealRow("snack", dishName("One more"), 100)
	row["day"] = day
	if status, body := call(t, server, http.MethodPost, "/v1/meals", token, row); status != http.StatusBadRequest || !strings.Contains(body["error"].(map[string]any)["message"].(string), "already has") {
		t.Fatalf("eleventh snack: %d %v", status, body)
	}

	cases := map[string]map[string]any{
		"no day":      {"slot": "lunch", "name": "X", "kcal": 1},
		"bad slot":    {"day": day, "slot": "brunch", "name": "X", "kcal": 1},
		"empty name":  {"day": day, "slot": "lunch", "name": "  ", "kcal": 1},
		"unknown key": {"day": day, "slot": "lunch", "name": "X", "kcal": 1, "surprise": true},
	}
	for label, body := range cases {
		if status, _ := call(t, server, http.MethodPost, "/v1/meals", token, body); status != http.StatusBadRequest {
			t.Errorf("%s: expected 400, got %d", label, status)
		}
	}
	if status, _ := call(t, server, http.MethodGet, "/v1/dishes?limit=0", token, nil); status != http.StatusBadRequest {
		t.Errorf("limit 0: expected 400, got %d", status)
	}
	if status, _ := call(t, server, http.MethodGet, "/v1/dishes?q=a", "", nil); status != http.StatusUnauthorized {
		t.Errorf("no token: expected 401, got %d", status)
	}
}

func TestImportFillsTheLibraryAndSearchEscapesWildcards(t *testing.T) {
	server, username, password := testServer(t)
	token := signIn(t, server, username, password)
	day := testDays(1)[0]
	name := dishName("Poha 100%")
	menu := map[string]any{"days": []any{map[string]any{"day": day, "meals": []any{mealRow("breakfast", name, 380), mealRow("breakfast", name, 390)}}}}
	if status, body := call(t, server, http.MethodPost, "/v1/meals/import", token, menu); status != http.StatusOK {
		t.Fatalf("import: %d %v", status, body)
	}
	found := dishesFor(t, server, token, strings.ToLower(name))
	if len(found) != 1 || found[0]["kcal"].(float64) != 390 {
		t.Fatalf("import should leave one library entry with the last numbers: %v", found)
	}
	for _, meal := range mealsOn(t, server, token, day, day) {
		if meal["dishId"] != found[0]["id"] {
			t.Fatalf("imported meal should point at the library dish: %v", meal)
		}
	}
	if got := dishesFor(t, server, token, "%"); len(got) != 0 {
		for _, dish := range got {
			if !strings.Contains(strings.ToLower(dish["name"].(string)), "%") {
				t.Fatalf("a bare %% should match only names with a percent sign, got %v", dish["name"])
			}
		}
	}
}
