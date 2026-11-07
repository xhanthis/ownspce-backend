package home

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// testServer opens the database named by HOME_TEST_DATABASE_URL and adds one fresh account.
// Tests skip when it is unset, because they need a real Postgres to mean anything.
func testServer(t *testing.T) (*httptest.Server, string, string) {
	t.Helper()
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
	hash, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if _, err := store.CreateUser(context.Background(), username, "Test Person", hash); err != nil {
		t.Fatalf("create user: %v", err)
	}
	server := httptest.NewServer(NewServer(store, Config{WebOrigins: []string{"https://home.example.invalid"}, AllowLocalhost: true}))
	t.Cleanup(server.Close)
	return server, username, "correct horse battery"
}

func call(t *testing.T, server *httptest.Server, method, path, token string, body any) (int, map[string]any) {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	request, _ := http.NewRequest(method, server.URL+path, reader)
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer response.Body.Close()
	decoded := map[string]any{}
	_ = json.NewDecoder(response.Body).Decode(&decoded)
	return response.StatusCode, decoded
}

func signIn(t *testing.T, server *httptest.Server, username, password string) string {
	t.Helper()
	status, body := call(t, server, http.MethodPost, "/v1/auth/login", "", map[string]string{"username": username, "password": password})
	if status != http.StatusOK {
		t.Fatalf("login status %d: %v", status, body)
	}
	return body["token"].(string)
}

func categoryOfKind(t *testing.T, server *httptest.Server, token, kind string) string {
	t.Helper()
	_, home := call(t, server, http.MethodGet, "/v1/home", token, nil)
	for _, raw := range home["categories"].([]any) {
		category := raw.(map[string]any)
		if category["kind"] == kind {
			return category["id"].(string)
		}
	}
	t.Fatalf("no %s category seeded", kind)
	return ""
}

func TestLoginRejectsWrongPasswordAndAcceptsTheRightOne(t *testing.T) {
	server, username, password := testServer(t)

	status, body := call(t, server, http.MethodPost, "/v1/auth/login", "", map[string]string{"username": username, "password": "wrong password"})
	if status != http.StatusUnauthorized || body["error"].(map[string]any)["code"] != "bad_login" {
		t.Fatalf("wrong password: %d %v", status, body)
	}

	token := signIn(t, server, strings.ToUpper(username), password)
	status, me := call(t, server, http.MethodGet, "/v1/me", token, nil)
	if status != http.StatusOK || me["username"] != username {
		t.Fatalf("me: %d %v", status, me)
	}
	if _, leaked := me["passwordHash"]; leaked {
		t.Fatal("password hash reached the response")
	}
}

func TestEveryLedgerRouteRefusesAMissingOrForgedToken(t *testing.T) {
	server, _, _ := testServer(t)
	for _, path := range []string{"/v1/me", "/v1/home", "/v1/entries?from=2026-01-01&to=2026-01-31"} {
		if status, _ := call(t, server, http.MethodGet, path, "", nil); status != http.StatusUnauthorized {
			t.Fatalf("%s without token: %d", path, status)
		}
		if status, _ := call(t, server, http.MethodGet, path, "test-token-not-real", nil); status != http.StatusUnauthorized {
			t.Fatalf("%s with forged token: %d", path, status)
		}
	}
}

func TestRepeatedFailedLoginsAreThrottledEvenWithTheRightPassword(t *testing.T) {
	server, username, password := testServer(t)
	for attempt := 0; attempt < loginFailures; attempt++ {
		call(t, server, http.MethodPost, "/v1/auth/login", "", map[string]string{"username": username, "password": "nope nope"})
	}
	status, _ := call(t, server, http.MethodPost, "/v1/auth/login", "", map[string]string{"username": username, "password": password})
	if status != http.StatusTooManyRequests {
		t.Fatalf("after %d failures: %d", loginFailures, status)
	}
}

func TestLogoutEndsTheSession(t *testing.T) {
	server, username, password := testServer(t)
	token := signIn(t, server, username, password)
	if status, _ := call(t, server, http.MethodPost, "/v1/auth/logout", token, nil); status != http.StatusNoContent {
		t.Fatalf("logout: %d", status)
	}
	if status, _ := call(t, server, http.MethodGet, "/v1/me", token, nil); status != http.StatusUnauthorized {
		t.Fatalf("token still works after logout: %d", status)
	}
}

func TestEntryLifecycle(t *testing.T) {
	server, username, password := testServer(t)
	token := signIn(t, server, username, password)
	expense := categoryOfKind(t, server, token, "expense")
	income := categoryOfKind(t, server, token, "income")
	_, me := call(t, server, http.MethodGet, "/v1/me", token, nil)

	draft := map[string]any{"occurredOn": "2026-03-14", "type": "expense", "amountMinor": 45000, "categoryId": expense, "note": "  Vegetables  ", "isShared": true, "paidBy": me["id"]}
	status, created := call(t, server, http.MethodPost, "/v1/entries", token, draft)
	if status != http.StatusCreated || created["note"] != "Vegetables" || created["occurredOn"] != "2026-03-14" {
		t.Fatalf("create: %d %v", status, created)
	}
	id := created["id"].(string)

	_, listed := call(t, server, http.MethodGet, "/v1/entries?from=2026-03-01&to=2026-03-31", token, nil)
	found := false
	for _, raw := range listed["entries"].([]any) {
		if raw.(map[string]any)["id"] == id {
			found = true
		}
	}
	if !found {
		t.Fatal("created entry not in its month")
	}

	draft["amountMinor"] = 50000
	draft["isShared"] = false
	status, replaced := call(t, server, http.MethodPut, "/v1/entries/"+id, token, draft)
	if status != http.StatusOK || replaced["amountMinor"].(float64) != 50000 || replaced["isShared"] != false {
		t.Fatalf("replace: %d %v", status, replaced)
	}

	mismatched := map[string]any{"occurredOn": "2026-03-14", "type": "expense", "amountMinor": 100, "categoryId": income, "note": "", "isShared": true, "paidBy": nil}
	if status, _ := call(t, server, http.MethodPost, "/v1/entries", token, mismatched); status != http.StatusBadRequest {
		t.Fatalf("expense under an income category: %d", status)
	}

	strangerPaid := map[string]any{"occurredOn": "2026-03-14", "type": "expense", "amountMinor": 100, "categoryId": expense, "note": "", "isShared": true, "paidBy": uuid.NewString()}
	if status, _ := call(t, server, http.MethodPost, "/v1/entries", token, strangerPaid); status != http.StatusBadRequest {
		t.Fatalf("payer who is not a member: %d", status)
	}

	if status, _ := call(t, server, http.MethodDelete, "/v1/entries/"+id, token, nil); status != http.StatusNoContent {
		t.Fatalf("remove: %d", status)
	}
	if status, _ := call(t, server, http.MethodDelete, "/v1/entries/"+id, token, nil); status != http.StatusNotFound {
		t.Fatalf("remove twice: %d", status)
	}
}

func TestEntryValidationRefusesBadInput(t *testing.T) {
	server, username, password := testServer(t)
	token := signIn(t, server, username, password)
	expense := categoryOfKind(t, server, token, "expense")

	cases := map[string]map[string]any{
		"zero amount":    {"occurredOn": "2026-03-14", "type": "expense", "amountMinor": 0, "categoryId": expense, "note": "", "isShared": true},
		"impossible day": {"occurredOn": "2026-02-30", "type": "expense", "amountMinor": 100, "categoryId": expense, "note": "", "isShared": true},
		"unknown type":   {"occurredOn": "2026-03-14", "type": "transfer", "amountMinor": 100, "categoryId": expense, "note": "", "isShared": true},
		"long note":      {"occurredOn": "2026-03-14", "type": "expense", "amountMinor": 100, "categoryId": expense, "note": strings.Repeat("x", 201), "isShared": true},
		"unknown field":  {"occurredOn": "2026-03-14", "type": "expense", "amountMinor": 100, "categoryId": expense, "note": "", "isShared": true, "createdBy": uuid.NewString()},
	}
	for name, body := range cases {
		if status, _ := call(t, server, http.MethodPost, "/v1/entries", token, body); status != http.StatusBadRequest {
			t.Errorf("%s: %d", name, status)
		}
	}
	if status, _ := call(t, server, http.MethodGet, "/v1/entries?from=2026-04-01&to=2026-03-01", token, nil); status != http.StatusBadRequest {
		t.Errorf("reversed range: %d", status)
	}
}

func TestSettingsSetAndClearTheOverallBudget(t *testing.T) {
	server, username, password := testServer(t)
	token := signIn(t, server, username, password)

	status, settings := call(t, server, http.MethodPatch, "/v1/settings", token, map[string]any{"overallBudgetMinor": 5000000})
	if status != http.StatusOK || settings["overallBudgetMinor"].(float64) != 5000000 {
		t.Fatalf("set: %d %v", status, settings)
	}
	status, settings = call(t, server, http.MethodPatch, "/v1/settings", token, map[string]any{"incomeTracking": true})
	if status != http.StatusOK || settings["overallBudgetMinor"].(float64) != 5000000 {
		t.Fatalf("an unrelated patch moved the budget: %d %v", status, settings)
	}
	status, settings = call(t, server, http.MethodPatch, "/v1/settings", token, map[string]any{"overallBudgetMinor": nil})
	if status != http.StatusOK || settings["overallBudgetMinor"] != nil {
		t.Fatalf("clear: %d %v", status, settings)
	}
	if status, _ := call(t, server, http.MethodPatch, "/v1/settings", token, map[string]any{"name": "   "}); status != http.StatusBadRequest {
		t.Fatalf("blank name: %d", status)
	}
}

func TestBudgetsGoOnExpenseCategoriesOnly(t *testing.T) {
	server, username, password := testServer(t)
	token := signIn(t, server, username, password)
	expense := categoryOfKind(t, server, token, "expense")
	income := categoryOfKind(t, server, token, "income")

	if status, _ := call(t, server, http.MethodPut, "/v1/budgets/"+income, token, map[string]any{"limitMinor": 1000}); status != http.StatusBadRequest {
		t.Fatalf("income budget: %d", status)
	}
	if status, _ := call(t, server, http.MethodPut, "/v1/budgets/"+expense, token, map[string]any{"limitMinor": 1000}); status != http.StatusOK {
		t.Fatalf("expense budget: %d", status)
	}
	if status, _ := call(t, server, http.MethodDelete, "/v1/budgets/"+expense, token, nil); status != http.StatusNoContent {
		t.Fatalf("remove budget: %d", status)
	}
}

func TestHoldingKeepsItsExactUnitCount(t *testing.T) {
	server, username, password := testServer(t)
	token := signIn(t, server, username, password)

	holding := map[string]any{"ownerId": nil, "name": "Index fund", "badge": "INDX", "assetType": "mutual_fund", "units": "12.345678", "avgCostMinor": 10000, "lastPriceMinor": 12000, "sipMinor": 0, "color": "#279AF4", "note": ""}
	status, created := call(t, server, http.MethodPost, "/v1/holdings", token, holding)
	if status != http.StatusCreated || created["units"] != "12.345678" {
		t.Fatalf("create: %d %v", status, created)
	}

	holding["units"] = "1e5"
	if status, _ := call(t, server, http.MethodPut, fmt.Sprintf("/v1/holdings/%s", created["id"]), token, holding); status != http.StatusBadRequest {
		t.Fatalf("scientific units: %d", status)
	}
	if status, _ := call(t, server, http.MethodDelete, fmt.Sprintf("/v1/holdings/%s", created["id"]), token, nil); status != http.StatusNoContent {
		t.Fatalf("remove: %d", status)
	}
}

func TestBrowsersGetCORSOnlyForAllowedOrigins(t *testing.T) {
	server, _, _ := testServer(t)

	cases := []struct {
		name    string
		origin  string
		allowed bool
	}{
		{"the configured web origin", "https://home.example.invalid", true},
		{"a localhost dev server outside production", "http://localhost:5173", true},
		{"a lookalike host", "https://home.example.invalid.attacker.invalid", false},
		{"a localhost prefix trick", "http://localhost.attacker.invalid", false},
		{"no origin at all", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request, _ := http.NewRequest(http.MethodOptions, server.URL+"/v1/entries", nil)
			request.Header.Set("Access-Control-Request-Method", http.MethodPost)
			if tc.origin != "" {
				request.Header.Set("Origin", tc.origin)
			}
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			got := response.Header.Get("Access-Control-Allow-Origin")
			if (tc.allowed && got != tc.origin) || (!tc.allowed && got != "") {
				t.Fatalf("allow-origin %q for %q", got, tc.origin)
			}
			if response.StatusCode != http.StatusNoContent {
				t.Fatalf("preflight status %d", response.StatusCode)
			}
		})
	}
}

func TestLoginThrottleHoldsAcrossServerInstances(t *testing.T) {
	first, username, password := testServer(t)
	store, err := Open(context.Background(), os.Getenv("HOME_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	second := httptest.NewServer(NewServer(store, Config{}))
	t.Cleanup(second.Close)

	for attempt := 0; attempt < loginFailures; attempt++ {
		call(t, first, http.MethodPost, "/v1/auth/login", "", map[string]string{"username": username, "password": "nope nope"})
	}
	status, _ := call(t, second, http.MethodPost, "/v1/auth/login", "", map[string]string{"username": username, "password": password})
	if status != http.StatusTooManyRequests {
		t.Fatalf("another instance let a throttled username in: %d", status)
	}
}

func TestASuccessfulLoginClearsEarlierFailures(t *testing.T) {
	server, username, password := testServer(t)
	for attempt := 0; attempt < loginFailures-1; attempt++ {
		call(t, server, http.MethodPost, "/v1/auth/login", "", map[string]string{"username": username, "password": "nope nope"})
	}
	signIn(t, server, username, password)
	call(t, server, http.MethodPost, "/v1/auth/login", "", map[string]string{"username": username, "password": "nope nope"})
	signIn(t, server, username, password)
}

func TestProductionConfigRefusesLocalhost(t *testing.T) {
	t.Setenv("ENV", "production")
	t.Setenv("HOME_WEB_ORIGINS", " https://money.example.invalid/ ,")
	config := ConfigFromEnv()
	if !config.originAllowed("https://money.example.invalid") {
		t.Fatal("configured origin refused")
	}
	if config.originAllowed("http://localhost:5173") {
		t.Fatal("localhost allowed in production")
	}
}

func TestSharedRefusesToStartWithoutADatabase(t *testing.T) {
	t.Setenv("HOME_DATABASE_URL", "")
	if _, err := Shared(context.Background()); err == nil {
		t.Fatal("Shared started with no HOME_DATABASE_URL")
	}
}

func TestImportAddsRowsOnceAndKeepsNothingFromABadFile(t *testing.T) {
	server, username, password := testServer(t)
	token := signIn(t, server, username, password)
	expense := categoryOfKind(t, server, token, "expense")
	income := categoryOfKind(t, server, token, "income")
	note := "import " + uuid.NewString()
	row := func(day string, amount int, category, kind string) map[string]any {
		return map[string]any{"occurredOn": day, "type": kind, "amountMinor": amount, "categoryId": category, "note": note, "isShared": true}
	}
	file := []any{row("2026-01-05", 2000, expense, "expense"), row("2026-01-05", 2000, expense, "expense"), row("2026-01-06", 90000, income, "income")}
	countInJanuary := func() int {
		_, listed := call(t, server, http.MethodGet, "/v1/entries?from=2026-01-01&to=2026-01-31", token, nil)
		found := 0
		for _, raw := range listed["entries"].([]any) {
			if raw.(map[string]any)["note"] == note {
				found++
			}
		}
		return found
	}

	status, preview := call(t, server, http.MethodPost, "/v1/entries/import", token, map[string]any{"entries": file, "dryRun": true})
	if status != http.StatusOK || preview["created"].(float64) != 3 || preview["duplicates"].(float64) != 0 || countInJanuary() != 0 {
		t.Fatalf("dry run: %d %v, stored %d", status, preview, countInJanuary())
	}

	status, first := call(t, server, http.MethodPost, "/v1/entries/import", token, map[string]any{"entries": file})
	if status != http.StatusOK || first["created"].(float64) != 3 || countInJanuary() != 3 {
		t.Fatalf("first import: %d %v, stored %d", status, first, countInJanuary())
	}

	status, again := call(t, server, http.MethodPost, "/v1/entries/import", token, map[string]any{"entries": append(file, row("2026-01-05", 2000, expense, "expense"))})
	if status != http.StatusOK || again["created"].(float64) != 1 || again["duplicates"].(float64) != 3 || countInJanuary() != 4 {
		t.Fatalf("second import: %d %v, stored %d", status, again, countInJanuary())
	}

	bad := []any{row("2026-01-07", 500, expense, "expense"), row("2026-01-07", 500, income, "expense")}
	if status, _ := call(t, server, http.MethodPost, "/v1/entries/import", token, map[string]any{"entries": bad}); status != http.StatusBadRequest || countInJanuary() != 4 {
		t.Fatalf("mixed-kind file: %d, stored %d", status, countInJanuary())
	}
	invalid := []any{row("2026-01-07", 500, expense, "expense"), row("2026-02-30", 500, expense, "expense")}
	status, refused := call(t, server, http.MethodPost, "/v1/entries/import", token, map[string]any{"entries": invalid})
	if status != http.StatusBadRequest || !strings.HasPrefix(refused["error"].(map[string]any)["message"].(string), "row 2:") || countInJanuary() != 4 {
		t.Fatalf("bad day: %d %v", status, refused)
	}

	if status, _ := call(t, server, http.MethodPost, "/v1/entries/import", token, map[string]any{"entries": []any{}}); status != http.StatusBadRequest {
		t.Fatalf("empty file: %d", status)
	}
	tooMany := make([]any, MaxImportRows+1)
	for index := range tooMany {
		tooMany[index] = row("2026-01-08", 100, expense, "expense")
	}
	if status, _ := call(t, server, http.MethodPost, "/v1/entries/import", token, map[string]any{"entries": tooMany}); status != http.StatusBadRequest {
		t.Fatalf("over the cap: %d", status)
	}
}
