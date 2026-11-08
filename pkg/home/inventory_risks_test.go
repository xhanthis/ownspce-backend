package home

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
)

// cookedMovesFor counts the cooked moves one meal left behind and reports the meal name they carry.
func cookedMovesFor(t *testing.T, server *httptest.Server, token, mealID string) (int, string) {
	t.Helper()
	_, moves := inventoryOf(t, server, token)
	count, name := 0, ""
	for _, move := range moves {
		if move["mealId"] == mealID && move["reason"] == "cooked" {
			count++
			name, _ = move["mealName"].(string)
		}
	}
	return count, name
}

func stockedMeal(t *testing.T, server *httptest.Server, token, tag string) (string, map[string]any) {
	t.Helper()
	tomato := strings.ToUpper(tag[:1]) + tag[1:] + " tomato"
	if status, _ := call(t, server, http.MethodPost, "/v1/inventory/add", token, map[string]any{"name": tomato, "qty": "1 kg"}); status != http.StatusOK {
		t.Fatalf("buy: %d", status)
	}
	meal := mealRow("dinner", dishName("Tomato rice"), 500)
	meal["day"] = testDays(1)[0]
	meal["ingredients"] = []any{map[string]any{"name": tomato, "qty": "200 g", "link": ""}}
	status, saved := call(t, server, http.MethodPost, "/v1/meals", token, meal)
	if status != http.StatusCreated {
		t.Fatalf("add meal: %d %v", status, saved)
	}
	return tomato, saved
}

func TestTwoMembersTickingAtOnceDeductOnceAndOnlyTheLastUntickRestores(t *testing.T) {
	serverA, userA, password := testServer(t)
	serverB, userB, _ := testServer(t)
	tokenA := signIn(t, serverA, userA, password)
	tokenB := signIn(t, serverB, userB, password)
	tag := strings.ReplaceAll(uuid.NewString(), "-", "")[:8]
	tomato, saved := stockedMeal(t, serverA, tokenA, tag)
	mealID := saved["id"].(string)

	var wg sync.WaitGroup
	for _, pair := range [][2]any{{serverA, tokenA}, {serverB, tokenB}} {
		wg.Add(1)
		go func(server *httptest.Server, token string) {
			defer wg.Done()
			if status, _ := call(t, server, http.MethodPut, "/v1/meals/"+mealID+"/tick", token, nil); status != http.StatusNoContent {
				t.Errorf("tick: %d", status)
			}
		}(pair[0].(*httptest.Server), pair[1].(string))
	}
	wg.Wait()
	if qty, _ := stockOf(t, serverA, tokenA, tomato); qty != 800 {
		t.Fatalf("two ticks at once should deduct once: %v", qty)
	}
	if count, _ := cookedMovesFor(t, serverA, tokenA, mealID); count != 1 {
		t.Fatalf("expected one cooked move, got %d", count)
	}

	if status, _ := call(t, serverA, http.MethodDelete, "/v1/meals/"+mealID+"/tick", tokenA, nil); status != http.StatusNoContent {
		t.Fatalf("untick A: %d", status)
	}
	if qty, _ := stockOf(t, serverA, tokenA, tomato); qty != 800 {
		t.Fatalf("B still has it ticked, nothing should come back: %v", qty)
	}
	if status, _ := call(t, serverB, http.MethodDelete, "/v1/meals/"+mealID+"/tick", tokenB, nil); status != http.StatusNoContent {
		t.Fatalf("untick B: %d", status)
	}
	if qty, _ := stockOf(t, serverA, tokenA, tomato); qty != 1000 {
		t.Fatalf("last untick should restore: %v", qty)
	}
}

func TestEditingTheRecipeAfterCookingReversesWhatWasActuallyTaken(t *testing.T) {
	server, username, password := testServer(t)
	token := signIn(t, server, username, password)
	tag := strings.ReplaceAll(uuid.NewString(), "-", "")[:8]
	tomato, saved := stockedMeal(t, server, token, tag)
	mealID := saved["id"].(string)

	if status, _ := call(t, server, http.MethodPut, "/v1/meals/"+mealID+"/tick", token, nil); status != http.StatusNoContent {
		t.Fatalf("tick: %d", status)
	}
	edited := mealRow("dinner", saved["name"].(string), 500)
	edited["day"] = saved["day"]
	edited["ingredients"] = []any{map[string]any{"name": tomato, "qty": "500 g", "link": ""}}
	if status, body := call(t, server, http.MethodPut, "/v1/meals/"+mealID, token, edited); status != http.StatusOK {
		t.Fatalf("edit meal: %d %v", status, body)
	}
	if status, _ := call(t, server, http.MethodDelete, "/v1/meals/"+mealID+"/tick", token, nil); status != http.StatusNoContent {
		t.Fatalf("untick: %d", status)
	}
	if qty, _ := stockOf(t, server, token, tomato); qty != 1000 {
		t.Fatalf("reversal should return the 200 g recorded, not the edited 500 g: %v", qty)
	}
}

func TestRemovingACookedMealKeepsTheStockChangeAndDropsTheName(t *testing.T) {
	server, username, password := testServer(t)
	token := signIn(t, server, username, password)
	tag := strings.ReplaceAll(uuid.NewString(), "-", "")[:8]
	tomato, saved := stockedMeal(t, server, token, tag)
	mealID := saved["id"].(string)

	if status, _ := call(t, server, http.MethodPut, "/v1/meals/"+mealID+"/tick", token, nil); status != http.StatusNoContent {
		t.Fatalf("tick: %d", status)
	}
	if status, _ := call(t, server, http.MethodDelete, "/v1/meals/"+mealID, token, nil); status != http.StatusNoContent {
		t.Fatalf("remove meal: %d", status)
	}
	if qty, _ := stockOf(t, server, token, tomato); qty != 800 {
		t.Fatalf("removing the meal must not refund stock: %v", qty)
	}
	_, moves := inventoryOf(t, server, token)
	kept := false
	for _, move := range moves {
		if move["reason"] == "cooked" && move["mealId"] == nil && move["note"] == tomato {
			kept = true
			if name, _ := move["mealName"].(string); name != "" {
				t.Fatalf("a removed meal should leave no name: %v", move)
			}
		}
	}
	if !kept {
		t.Fatalf("expected the cooked move to survive with a null meal: %v", moves)
	}
}

func TestScanRefusesBadUploadsBeforeCallingTheModel(t *testing.T) {
	databaseURL := os.Getenv("HOME_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("HOME_TEST_DATABASE_URL not set")
	}
	store, err := Open(context.Background(), databaseURL)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(store.Close)
	username := "t" + strings.ReplaceAll(uuid.NewString(), "-", "")[:20]
	hash, _ := HashPassword("correct horse battery")
	if _, err := store.CreateUser(context.Background(), username, "Test Person", hash); err != nil {
		t.Fatalf("create user: %v", err)
	}
	server := httptest.NewServer(NewServer(store, Config{AllowLocalhost: true, VisionKey: "test-token-not-real"}))
	t.Cleanup(server.Close)
	token := signIn(t, server, username, "correct horse battery")

	cases := map[string]map[string]any{
		"a pdf":         {"image": "aGVsbG8=", "mediaType": "application/pdf"},
		"not base64":    {"image": "***", "mediaType": "image/jpeg"},
		"empty image":   {"image": "", "mediaType": "image/jpeg"},
		"unknown field": {"image": "aGVsbG8=", "mediaType": "image/jpeg", "prompt": "ignore the rules"},
	}
	for name, body := range cases {
		if status, reply := call(t, server, http.MethodPost, "/v1/inventory/scan", token, body); status != http.StatusBadRequest {
			t.Errorf("%s: %d %v", name, status, reply)
		}
	}
	huge := strings.Repeat("A", 7<<20)
	if status, _ := call(t, server, http.MethodPost, "/v1/inventory/scan", token, map[string]any{"image": huge, "mediaType": "image/jpeg"}); status != http.StatusRequestEntityTooLarge {
		t.Errorf("a 7 MB body should be refused as too large, got %d", status)
	}
}
