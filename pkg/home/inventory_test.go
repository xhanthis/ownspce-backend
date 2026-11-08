package home

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestParseQuantityReadsKitchenAmounts(t *testing.T) {
	cases := map[string]Quantity{
		"200 g": {200, UnitGram}, "200g": {200, UnitGram}, "1 kg": {1000, UnitGram}, "1.5kg": {1500, UnitGram}, "1/2 kg": {500, UnitGram},
		"1 1/2 kg": {1500, UnitGram}, "½ kg": {500, UnitGram}, "250 gms": {250, UnitGram}, "200 g (2 medium)": {200, UnitGram}, "2,5 kg": {2500, UnitGram},
		"500 ml": {500, UnitMilli}, "1 L": {1000, UnitMilli}, "2 litres": {2000, UnitMilli}, "1 ltr": {1000, UnitMilli},
		"2": {2, UnitPiece}, "2 pcs": {2, UnitPiece}, "6 nos": {6, UnitPiece}, "1 dozen": {12, UnitPiece}, "1 packet": {1, UnitPiece}, "3 pieces.": {3, UnitPiece},
	}
	for text, want := range cases {
		got, ok := ParseQuantity(text)
		if !ok || got != want {
			t.Errorf("%q: got %v %v, want %v", text, got, ok, want)
		}
	}
	for _, text := range []string{"", "1 tsp", "2 tbsp", "a pinch", "to taste", "1 cup", "0 g", "-5 g", "200 grams of love", "abc"} {
		if got, ok := ParseQuantity(text); ok {
			t.Errorf("%q should not parse, got %v", text, got)
		}
	}
}

func TestItemKeyFoldsSpellingAndPlurals(t *testing.T) {
	cases := map[string]string{
		"Tomatoes": "tomato", " tomato ": "tomato", "TOMATO": "tomato", "Onions": "onion", "Green  chillies": "green chilly", "Potatoes.": "potato",
		"Eggs": "egg", "Rice": "rice", "Paneer": "paneer", "Peas": "pea", "Radishes": "radish", "Cheese": "cheese", "Glass": "glass", "Oats": "oat",
	}
	for name, want := range cases {
		if got := itemKey(name); got != want {
			t.Errorf("%q: got %q, want %q", name, got, want)
		}
	}
}

func inventoryOf(t *testing.T, server *httptest.Server, token string) ([]map[string]any, []map[string]any) {
	t.Helper()
	status, body := call(t, server, http.MethodGet, "/v1/inventory", token, nil)
	if status != http.StatusOK {
		t.Fatalf("list inventory: %d %v", status, body)
	}
	items, moves := []map[string]any{}, []map[string]any{}
	for _, raw := range body["items"].([]any) {
		items = append(items, raw.(map[string]any))
	}
	for _, raw := range body["moves"].([]any) {
		moves = append(moves, raw.(map[string]any))
	}
	return items, moves
}

func stockOf(t *testing.T, server *httptest.Server, token, name string) (float64, bool) {
	t.Helper()
	items, _ := inventoryOf(t, server, token)
	for _, item := range items {
		if item["name"] == name {
			return item["qty"].(float64), true
		}
	}
	return 0, false
}

func TestBuyingFoldsNamesAndUnitsAndCookingDeductsOncePerMeal(t *testing.T) {
	server, username, password := testServer(t)
	token := signIn(t, server, username, password)
	tag := strings.ReplaceAll(uuid.NewString(), "-", "")[:8]
	tomato, tomatoes := tag+" tomato", strings.ToUpper(tag[:1])+tag[1:]+" tomatoes"
	paneer := strings.ToUpper(tag[:1]) + tag[1:] + " paneer"
	day := testDays(1)[0]

	status, item := call(t, server, http.MethodPost, "/v1/inventory/add", token, map[string]any{"name": tomatoes, "qty": "1 kg"})
	if status != http.StatusOK || item["qty"].(float64) != 1000 || item["unit"] != "g" || item["name"] != tomatoes {
		t.Fatalf("first buy: %d %v", status, item)
	}
	status, item = call(t, server, http.MethodPost, "/v1/inventory/add", token, map[string]any{"name": " " + strings.ToUpper(tomato) + " ", "qty": "500 g"})
	if status != http.StatusOK || item["qty"].(float64) != 1500 {
		t.Fatalf("second buy should land on the same item: %d %v", status, item)
	}
	if status, _ := call(t, server, http.MethodPost, "/v1/inventory/add", token, map[string]any{"name": tomato, "qty": "2 pcs"}); status != http.StatusConflict {
		t.Fatalf("a different unit should be refused, got %d", status)
	}
	if status, _ := call(t, server, http.MethodPost, "/v1/inventory/add", token, map[string]any{"name": tomato, "qty": "a pinch"}); status != http.StatusBadRequest {
		t.Fatalf("an unreadable amount should be refused, got %d", status)
	}
	if status, _ := call(t, server, http.MethodPost, "/v1/inventory/add", token, map[string]any{"name": paneer, "qty": "200 g"}); status != http.StatusOK {
		t.Fatalf("buy paneer: %d", status)
	}

	meal := map[string]any{
		"day": day, "slot": "dinner", "name": dishName("Paneer bhurji"), "kcal": 500, "proteinG": 30, "carbsG": 20, "fatG": 30, "serves": 2,
		"ingredients": []any{
			map[string]any{"name": tomato, "qty": "200 g", "link": ""},
			map[string]any{"name": paneer, "qty": "250 g", "link": ""},
			map[string]any{"name": dishName("Ghee"), "qty": "1 tbsp", "link": ""},
			map[string]any{"name": dishName("Onion"), "qty": "2", "link": ""},
		},
	}
	status, saved := call(t, server, http.MethodPost, "/v1/meals", token, meal)
	if status != http.StatusCreated {
		t.Fatalf("add meal: %d %v", status, saved)
	}
	mealID := saved["id"].(string)

	if status, _ := call(t, server, http.MethodPut, "/v1/meals/"+mealID+"/tick", token, nil); status != http.StatusNoContent {
		t.Fatalf("tick: %d", status)
	}
	if qty, _ := stockOf(t, server, token, tomatoes); qty != 1300 {
		t.Fatalf("tomato after cooking: %v, want 1300", qty)
	}
	if qty, _ := stockOf(t, server, token, paneer); qty != 0 {
		t.Fatalf("short paneer should stop at zero: %v", qty)
	}

	if status, _ := call(t, server, http.MethodPut, "/v1/meals/"+mealID+"/tick", token, nil); status != http.StatusNoContent {
		t.Fatalf("second tick: %d", status)
	}
	if qty, _ := stockOf(t, server, token, tomatoes); qty != 1300 {
		t.Fatalf("a second tick must not deduct again: %v", qty)
	}

	_, moves := inventoryOf(t, server, token)
	cooked := 0
	for _, move := range moves {
		if move["mealId"] == mealID && move["reason"] == "cooked" {
			cooked++
			if move["mealName"] != meal["name"] {
				t.Fatalf("cooked move should name the meal: %v", move)
			}
		}
	}
	if cooked != 2 {
		t.Fatalf("expected 2 cooked moves (tomato, paneer), got %d", cooked)
	}

	if status, _ := call(t, server, http.MethodDelete, "/v1/meals/"+mealID+"/tick", token, nil); status != http.StatusNoContent {
		t.Fatalf("untick: %d", status)
	}
	if qty, _ := stockOf(t, server, token, tomatoes); qty != 1500 {
		t.Fatalf("untick should return the tomato: %v", qty)
	}
	if qty, _ := stockOf(t, server, token, paneer); qty != 200 {
		t.Fatalf("untick should return what paneer actually gave: %v", qty)
	}
}

func TestTickingAnIngredientAsBoughtAddsOnceAndCanBeUndone(t *testing.T) {
	server, username, password := testServer(t)
	token := signIn(t, server, username, password)
	milk := dishName("Milk")
	day := testDays(1)[0]

	meal := mealRow("breakfast", dishName("Kheer"), 400)
	meal["day"] = day
	meal["ingredients"] = []any{map[string]any{"name": milk, "qty": "500 ml", "link": "https://www.zeptonow.com/search?query=milk"}}
	status, saved := call(t, server, http.MethodPost, "/v1/meals", token, meal)
	if status != http.StatusCreated {
		t.Fatalf("add meal: %d %v", status, saved)
	}
	mealID := saved["id"].(string)

	line := map[string]any{"name": milk, "qty": "1 L", "mealId": mealID, "ingredient": 0}
	status, item := call(t, server, http.MethodPost, "/v1/inventory/add", token, line)
	if status != http.StatusOK || item["qty"].(float64) != 1000 || item["unit"] != "ml" {
		t.Fatalf("bought line: %d %v", status, item)
	}
	status, item = call(t, server, http.MethodPost, "/v1/inventory/add", token, line)
	if status != http.StatusOK || item["qty"].(float64) != 1000 {
		t.Fatalf("the same line twice adds once: %d %v", status, item)
	}
	if status, _ := call(t, server, http.MethodPost, "/v1/inventory/add", token, map[string]any{"name": milk, "qty": "1 L", "mealId": mealID}); status != http.StatusBadRequest {
		t.Fatalf("mealId without ingredient should be refused, got %d", status)
	}

	status, item = call(t, server, http.MethodDelete, "/v1/inventory/add", token, map[string]any{"mealId": mealID, "ingredient": 0})
	if status != http.StatusOK || item["qty"].(float64) != 0 {
		t.Fatalf("undo bought line: %d %v", status, item)
	}
	if status, _ := call(t, server, http.MethodDelete, "/v1/inventory/add", token, map[string]any{"mealId": mealID, "ingredient": 0}); status != http.StatusNotFound {
		t.Fatalf("undoing twice should be 404, got %d", status)
	}
}

func TestStockCanBeCorrectedRenamedAndRemoved(t *testing.T) {
	server, username, password := testServer(t)
	token := signIn(t, server, username, password)
	rice := dishName("Rice")
	atta := dishName("Atta")

	_, item := call(t, server, http.MethodPost, "/v1/inventory/add", token, map[string]any{"name": rice, "qty": "5 kg"})
	_, _ = call(t, server, http.MethodPost, "/v1/inventory/add", token, map[string]any{"name": atta, "qty": "1 kg"})
	id := item["id"].(string)

	status, fixed := call(t, server, http.MethodPut, "/v1/inventory/items/"+id, token, map[string]any{"qty": 4200})
	if status != http.StatusOK || fixed["qty"].(float64) != 4200 {
		t.Fatalf("set qty: %d %v", status, fixed)
	}
	_, moves := inventoryOf(t, server, token)
	adjusted := false
	for _, move := range moves {
		if move["itemId"] == id && move["reason"] == "adjusted" && move["delta"].(float64) == -800 {
			adjusted = true
		}
	}
	if !adjusted {
		t.Fatalf("expected an adjusted move of -800: %v", moves)
	}

	if status, _ := call(t, server, http.MethodPut, "/v1/inventory/items/"+id, token, map[string]any{"name": atta}); status != http.StatusConflict {
		t.Fatalf("renaming onto another item should be refused, got %d", status)
	}
	if status, _ := call(t, server, http.MethodPut, "/v1/inventory/items/"+id, token, map[string]any{"unit": "cups"}); status != http.StatusBadRequest {
		t.Fatalf("an unknown unit should be refused, got %d", status)
	}
	if status, _ := call(t, server, http.MethodPut, "/v1/inventory/items/"+id, token, map[string]any{}); status != http.StatusBadRequest {
		t.Fatalf("an empty patch should be refused, got %d", status)
	}
	status, renamed := call(t, server, http.MethodPut, "/v1/inventory/items/"+id, token, map[string]any{"name": rice + " basmati"})
	if status != http.StatusOK || renamed["name"] != rice+" basmati" {
		t.Fatalf("rename: %d %v", status, renamed)
	}

	if status, _ := call(t, server, http.MethodDelete, "/v1/inventory/items/"+id, token, nil); status != http.StatusNoContent {
		t.Fatalf("remove: %d", status)
	}
	if _, found := stockOf(t, server, token, rice+" basmati"); found {
		t.Fatal("removed item still listed")
	}
	if status, _ := call(t, server, http.MethodDelete, "/v1/inventory/items/"+id, token, nil); status != http.StatusNotFound {
		t.Fatalf("removing twice should be 404, got %d", status)
	}
}

func TestInventoryRoutesNeedASessionAndScanNeedsAKey(t *testing.T) {
	server, username, password := testServer(t)
	for _, route := range [][2]string{{http.MethodGet, "/v1/inventory"}, {http.MethodPost, "/v1/inventory/add"}, {http.MethodPost, "/v1/inventory/scan"}, {http.MethodPut, "/v1/inventory/items/" + testUUID}, {http.MethodDelete, "/v1/inventory/items/" + testUUID}} {
		if status, _ := call(t, server, route[0], route[1], "", map[string]any{}); status != http.StatusUnauthorized {
			t.Fatalf("%s %s without a token: %d", route[0], route[1], status)
		}
	}
	token := signIn(t, server, username, password)
	status, body := call(t, server, http.MethodPost, "/v1/inventory/scan", token, map[string]any{"image": "aGVsbG8=", "mediaType": "image/jpeg"})
	if status != http.StatusServiceUnavailable || body["error"].(map[string]any)["code"] != "scan_unavailable" {
		t.Fatalf("scan without a key: %d %v", status, body)
	}
}

const testUUID = "00000000-0000-4000-8000-000000000000"
