package home

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestDefaultLibraryIsValidAndWellFormed(t *testing.T) {
	dishes, err := defaultDishes()
	if err != nil {
		t.Fatal(err)
	}
	if len(dishes) < 80 {
		t.Fatalf("expected the full library, got %d dishes", len(dishes))
	}
	for _, dish := range dishes {
		switch {
		case dish.Serves != 2:
			t.Errorf("%s: library dishes are for two, got serves %d", dish.Name, dish.Serves)
		case dish.Kcal < 20 || dish.Kcal > 900:
			t.Errorf("%s: %d kcal is not a home portion", dish.Name, dish.Kcal)
		case len(dish.Ingredients) == 0:
			t.Errorf("%s: no ingredients, inventory cannot follow it", dish.Name)
		}
		for _, ingredient := range dish.Ingredients {
			if _, ok := ParseQuantity(ingredient.Qty); !ok {
				t.Errorf("%s: %q %q is not a quantity the inventory understands", dish.Name, ingredient.Name, ingredient.Qty)
			}
		}
	}
}

func TestSeedDishesRunsOnceAndKeepsAHandEdit(t *testing.T) {
	server, username, password := testServer(t)
	token := signIn(t, server, username, password)
	store, err := Open(context.Background(), os.Getenv("HOME_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(store.Close)

	if _, err := store.SeedDishes(context.Background()); err != nil {
		t.Fatalf("first seed: %v", err)
	}
	if added, err := store.SeedDishes(context.Background()); err != nil || added != 0 {
		t.Fatalf("second seed should add nothing, got %d %v", added, err)
	}

	found := dishesFor(t, server, token, "kanda pohe")
	if len(found) == 0 || found[0]["name"] != "Kanda Pohe" || found[0]["serves"].(float64) != 2 {
		t.Fatalf("seeded dish missing from search: %v", found)
	}
	original := int(found[0]["kcal"].(float64))

	edit := mealRow("breakfast", "Kanda Pohe", original+123)
	edit["day"] = testDays(1)[0]
	edit["saveToLibrary"] = true
	if status, _ := call(t, server, http.MethodPost, "/v1/meals", token, edit); status != http.StatusCreated {
		t.Fatalf("edit through add: %d", status)
	}
	if _, err := store.SeedDishes(context.Background()); err != nil {
		t.Fatalf("reseed: %v", err)
	}
	found = dishesFor(t, server, token, "kanda pohe")
	if int(found[0]["kcal"].(float64)) != original+123 {
		t.Fatalf("reseed overwrote a hand edit: %v", found[0])
	}

	restore := mealRow("breakfast", "Kanda Pohe", original)
	restore["day"] = testDays(1)[0]
	restore["saveToLibrary"] = true
	if status, _ := call(t, server, http.MethodPost, "/v1/meals", token, restore); status != http.StatusCreated {
		t.Fatalf("restore: %d", status)
	}
}

func TestServerlessBootstrapSeedsTheLibrary(t *testing.T) {
	databaseURL := os.Getenv("HOME_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("HOME_TEST_DATABASE_URL not set")
	}
	t.Setenv("HOME_DATABASE_URL", databaseURL)
	resetShared := func() {
		sharedMu.Lock()
		sharedHandler = nil
		sharedMu.Unlock()
	}
	resetShared()
	t.Cleanup(resetShared)
	handler, err := Shared(context.Background())
	if err != nil {
		t.Fatalf("shared: %v", err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

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
	token := signIn(t, server, username, "correct horse battery")
	found := dishesFor(t, server, token, "pithla bhakri")
	if len(found) == 0 || found[0]["name"] != "Pithla Bhakri" {
		t.Fatalf("the serverless path did not seed the library: %v", found)
	}
}
