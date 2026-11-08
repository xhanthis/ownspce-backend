package home

import (
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// testDays picks consecutive days far in the future at random, so runs against a shared database never
// see each other's plans.
func testDays(count int) []string {
	base := time.Date(2100+rand.IntN(800), time.Month(1+rand.IntN(12)), 1+rand.IntN(20), 0, 0, 0, 0, time.UTC)
	days := make([]string, count)
	for index := range days {
		days[index] = base.AddDate(0, 0, index).Format("2006-01-02")
	}
	return days
}

func mealRow(slot, name string, kcal int) map[string]any {
	return map[string]any{
		"slot": slot, "name": name, "kcal": kcal, "proteinG": 20, "carbsG": 50, "fatG": 10, "serves": 2,
		"ingredients": []any{map[string]any{"name": "Paneer", "qty": "200 g", "link": "https://www.zeptonow.com/search?query=paneer"}},
	}
}

func mealsOn(t *testing.T, server *httptest.Server, token, from, to string) []map[string]any {
	t.Helper()
	status, listed := call(t, server, http.MethodGet, "/v1/meals?from="+from+"&to="+to, token, nil)
	if status != http.StatusOK {
		t.Fatalf("list meals: %d %v", status, listed)
	}
	out := []map[string]any{}
	for _, raw := range listed["meals"].([]any) {
		out = append(out, raw.(map[string]any))
	}
	return out
}

func TestMealImportReplacesOnlyThePastedDaysAndKeepsTheRest(t *testing.T) {
	server, username, password := testServer(t)
	token := signIn(t, server, username, password)
	days := testDays(3)
	day1, day2, day3 := days[0], days[1], days[2]

	first := map[string]any{"days": []any{
		map[string]any{"day": day1, "meals": []any{mealRow("breakfast", "Poha", 380), mealRow("dinner", "Dal rice", 700)}},
		map[string]any{"day": day2, "meals": []any{mealRow("lunch", "Rajma chawal", 680)}},
	}}
	status, preview := call(t, server, http.MethodPost, "/v1/meals/import", token, map[string]any{"days": first["days"], "dryRun": true})
	if status != http.StatusOK || preview["days"].(float64) != 2 || preview["meals"].(float64) != 3 || preview["replaced"].(float64) != 0 {
		t.Fatalf("dry run: %d %v", status, preview)
	}
	if got := mealsOn(t, server, token, day1, day3); len(got) != 0 {
		t.Fatalf("dry run wrote %d meals", len(got))
	}

	status, result := call(t, server, http.MethodPost, "/v1/meals/import", token, first)
	if status != http.StatusOK || result["meals"].(float64) != 3 || result["replaced"].(float64) != 0 {
		t.Fatalf("first import: %d %v", status, result)
	}
	got := mealsOn(t, server, token, day1, day3)
	if len(got) != 3 || got[0]["day"] != day2 || got[1]["slot"] != "breakfast" || got[2]["slot"] != "dinner" {
		t.Fatalf("after first import: %v", got)
	}
	if ingredients := got[1]["ingredients"].([]any); len(ingredients) != 1 || ingredients[0].(map[string]any)["link"] != "https://www.zeptonow.com/search?query=paneer" {
		t.Fatalf("ingredients lost: %v", got[1])
	}

	second := map[string]any{"days": []any{
		map[string]any{"day": day1, "meals": []any{mealRow("breakfast", "Masala oats", 320)}},
		map[string]any{"day": day3, "meals": []any{mealRow("dinner", "Egg curry", 650)}},
	}}
	status, result = call(t, server, http.MethodPost, "/v1/meals/import", token, second)
	if status != http.StatusOK || result["replaced"].(float64) != 1 {
		t.Fatalf("second import: %d %v", status, result)
	}
	names := []string{}
	for _, meal := range mealsOn(t, server, token, day1, day3) {
		names = append(names, meal["day"].(string)+" "+meal["name"].(string))
	}
	if strings.Join(names, ", ") != day3+" Egg curry, "+day2+" Rajma chawal, "+day1+" Masala oats" {
		t.Fatalf("after second import: %v", names)
	}
}

func TestMealImportRefusesBadMenusWholesale(t *testing.T) {
	server, username, password := testServer(t)
	token := signIn(t, server, username, password)
	day := testDays(1)[0]
	cases := []struct {
		name string
		body map[string]any
		want string
	}{
		{"no days", map[string]any{"days": []any{}}, "between 1 and"},
		{"bad day", map[string]any{"days": []any{map[string]any{"day": "2031-02-30", "meals": []any{mealRow("lunch", "x", 1)}}}}, "not a yyyy-mm-dd"},
		{"day twice", map[string]any{"days": []any{map[string]any{"day": day, "meals": []any{mealRow("lunch", "x", 1)}}, map[string]any{"day": day, "meals": []any{mealRow("dinner", "y", 1)}}}}, "listed twice"},
		{"empty day", map[string]any{"days": []any{map[string]any{"day": day, "meals": []any{}}}}, "needs 1 to"},
		{"bad slot", map[string]any{"days": []any{map[string]any{"day": day, "meals": []any{mealRow("brunch", "x", 1)}}}}, "meal 1: slot"},
		{"blank name", map[string]any{"days": []any{map[string]any{"day": day, "meals": []any{mealRow("lunch", "   ", 1)}}}}, "name must be"},
		{"kcal too high", map[string]any{"days": []any{map[string]any{"day": day, "meals": []any{mealRow("lunch", "x", maxKcal+1)}}}}, "kcal must be"},
		{"javascript link", map[string]any{"days": []any{map[string]any{"day": day, "meals": []any{map[string]any{
			"slot": "lunch", "name": "x", "kcal": 1, "ingredients": []any{map[string]any{"name": "Onion", "qty": "2", "link": "javascript:alert(1)"}},
		}}}}}, "https address"},
		{"unknown field", map[string]any{"days": []any{map[string]any{"day": day, "meals": []any{mealRow("lunch", "x", 1)}}}, "overwrite": true}, "not valid JSON"},
	}
	for _, tc := range cases {
		status, refused := call(t, server, http.MethodPost, "/v1/meals/import", token, tc.body)
		message, _ := refused["error"].(map[string]any)["message"].(string)
		if status != http.StatusBadRequest || !strings.Contains(message, tc.want) {
			t.Errorf("%s: %d %q", tc.name, status, message)
		}
	}
	if got := mealsOn(t, server, token, day, day); len(got) != 0 {
		t.Fatalf("a refused menu wrote %d meals", len(got))
	}
}

func TestMealTicksArePerMemberAndSurviveAnEdit(t *testing.T) {
	server, username, password := testServer(t)
	token := signIn(t, server, username, password)
	_, me := call(t, server, http.MethodGet, "/v1/me", token, nil)
	day := testDays(1)[0]
	call(t, server, http.MethodPost, "/v1/meals/import", token, map[string]any{"days": []any{map[string]any{"day": day, "meals": []any{mealRow("lunch", "Khichdi", 500)}}}})
	meal := mealsOn(t, server, token, day, day)[0]
	id := meal["id"].(string)
	if len(meal["tickedBy"].([]any)) != 0 {
		t.Fatalf("new meal already ticked: %v", meal)
	}

	for range 2 {
		if status, _ := call(t, server, http.MethodPut, "/v1/meals/"+id+"/tick", token, nil); status != http.StatusNoContent {
			t.Fatalf("tick: %d", status)
		}
	}
	ticked := mealsOn(t, server, token, day, day)[0]["tickedBy"].([]any)
	if len(ticked) != 1 || ticked[0] != me["id"] {
		t.Fatalf("ticked twice should be one tick by me: %v", ticked)
	}

	edit := mealRow("lunch", "Khichdi with ghee", 560)
	edit["day"] = day
	status, replaced := call(t, server, http.MethodPut, "/v1/meals/"+id, token, edit)
	if status != http.StatusOK || replaced["name"] != "Khichdi with ghee" || len(replaced["tickedBy"].([]any)) != 1 {
		t.Fatalf("edit should keep the tick: %d %v", status, replaced)
	}

	if status, _ := call(t, server, http.MethodDelete, "/v1/meals/"+id+"/tick", token, nil); status != http.StatusNoContent {
		t.Fatalf("untick: %d", status)
	}
	if status, _ := call(t, server, http.MethodDelete, "/v1/meals/"+id+"/tick", token, nil); status != http.StatusNoContent {
		t.Fatalf("untick twice should be fine: %d", status)
	}
	if ticked := mealsOn(t, server, token, day, day)[0]["tickedBy"].([]any); len(ticked) != 0 {
		t.Fatalf("still ticked: %v", ticked)
	}

	if status, _ := call(t, server, http.MethodPut, "/v1/meals/"+uuid.NewString()+"/tick", token, nil); status != http.StatusNotFound {
		t.Fatalf("tick a meal that is not there: %d", status)
	}
	if status, _ := call(t, server, http.MethodDelete, "/v1/meals/"+id, token, nil); status != http.StatusNoContent {
		t.Fatalf("remove: %d", status)
	}
	if status, _ := call(t, server, http.MethodDelete, "/v1/meals/"+id, token, nil); status != http.StatusNotFound {
		t.Fatalf("remove twice: %d", status)
	}
	if status, _ := call(t, server, http.MethodGet, "/v1/meals?from=2031-03-02&to=2031-03-01", token, nil); status != http.StatusBadRequest {
		t.Fatalf("from after to: %d", status)
	}
}

func TestMealRoutesRefuseAMissingToken(t *testing.T) {
	server, _, _ := testServer(t)
	for _, route := range []struct{ method, path string }{
		{http.MethodGet, "/v1/meals?from=2031-01-01&to=2031-01-02"},
		{http.MethodPost, "/v1/meals/import"},
		{http.MethodPut, "/v1/meals/" + uuid.NewString()},
		{http.MethodDelete, "/v1/meals/" + uuid.NewString()},
		{http.MethodPut, "/v1/meals/" + uuid.NewString() + "/tick"},
	} {
		if status, _ := call(t, server, route.method, route.path, "", nil); status != http.StatusUnauthorized {
			t.Errorf("%s %s without a token: %d", route.method, route.path, status)
		}
	}
}
