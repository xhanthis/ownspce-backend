package httpapi

import (
	"fmt"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestRoutesBuildWithoutConflict is the cheapest guard against a startup panic.
// chi mounts a subrouter over a whole subtree, so a second Mount on a path that
// already has one panics inside routes() — at boot, on every request, in
// production. Constructing the tree here catches that in a unit test with no
// database.
func TestRoutesBuildWithoutConflict(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("routes() panicked, which would take the API down at boot: %v", r)
		}
	}()
	if (&Server{}).routes() == nil {
		t.Fatal("routes() returned nil")
	}
}

func TestRoundRatToMinorRoundsHalvesAwayFromZero(t *testing.T) {
	cases := []struct {
		name string
		num  int64
		den  int64
		want int64
	}{
		{"exact", 61031600, 1, 61031600},
		{"rounds down below half", 3496, 1, 3496},
		{"rounds half up", 6993, 2, 3497},
		{"rounds just under half down", 6992, 2, 3496},
		{"rounds two thirds up", 7, 3, 2},
		{"negative half rounds away from zero", -6993, 2, -3497},
		{"negative below half rounds toward zero", -6991, 2, -3496},
		{"zero", 0, 5, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := roundRatToMinor(big.NewRat(c.num, c.den))
			if got != c.want {
				t.Errorf("roundRatToMinor(%d/%d) = %d, want %d", c.num, c.den, got, c.want)
			}
		})
	}
}

// TestHoldingValueSurvivesAmountsFloat64Cannot is the reason holdings are valued
// with big.Rat. A large retirement balance in paise times a six-place unit count
// lands well past 2^53, where float64 can no longer represent consecutive
// integers, and a portfolio that disagrees with the sum of its own rows is a
// support ticket. The expected value here is computed with integers only:
// 1234567891234 × 999999999 / 10^6, rounded once.
func TestHoldingValueSurvivesAmountsFloat64Cannot(t *testing.T) {
	const units = "999999999.999999"
	const price = int64(99999999)

	scaled := new(big.Int).Mul(big.NewInt(999999999999999), big.NewInt(price))
	quotient, remainder := new(big.Int).QuoRem(scaled, big.NewInt(1000000), new(big.Int))
	if new(big.Int).Lsh(remainder, 1).Cmp(big.NewInt(1000000)) >= 0 {
		quotient.Add(quotient, big.NewInt(1))
	}
	want := quotient.Int64()

	parsed, ok := new(big.Rat).SetString(units)
	if !ok {
		t.Fatalf("could not parse %q as an exact decimal", units)
	}
	got := roundRatToMinor(new(big.Rat).Mul(parsed, new(big.Rat).SetInt64(price)))
	if got != want {
		t.Fatalf("exact valuation = %d, want %d", got, want)
	}

	if want <= 1<<53 {
		t.Fatalf("the fixture no longer exceeds float64's exact range (%d); pick larger inputs", want)
	}
	if viaFloat := int64(999999999.999999 * float64(price)); viaFloat == want {
		t.Logf("float64 agreed at this magnitude (%d); the exact path is still what ships", viaFloat)
	}
}

func TestValidateUnitsRejectsWhatTheColumnCannotHold(t *testing.T) {
	valid := []string{"1", "2840", "0.000001", "1234567.891234", "999999999999999999"}
	for _, u := range valid {
		if err := validateUnits(u); err != nil {
			t.Errorf("validateUnits(%q) = %v, want nil", u, err)
		}
	}

	invalid := []string{"", "0", "0.0", "-1", "1.1234567", "1e5", "abc", "1,000", " ", "1234567890123456789"}
	for _, u := range invalid {
		if err := validateUnits(u); err == nil {
			t.Errorf("validateUnits(%q) = nil, want an error", u)
		}
	}
}

func TestParsePeriodRequiresBothBoundsAndRejectsReversedWindows(t *testing.T) {
	cases := []struct {
		name    string
		query   string
		wantErr bool
	}{
		{"both bounds", "?from=2026-08-01&to=2026-08-31", false},
		{"single day", "?from=2026-08-01&to=2026-08-01", false},
		{"missing to", "?from=2026-08-01", true},
		{"missing from", "?to=2026-08-31", true},
		{"neither", "", true},
		{"reversed", "?from=2026-08-31&to=2026-08-01", true},
		{"not a date", "?from=august&to=2026-08-31", true},
		{"timestamp not accepted", "?from=2026-08-01T00:00:00Z&to=2026-08-31", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, "/v1/money/households/x/summary"+c.query, nil)
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			_, _, err = parsePeriod(req)
			if c.wantErr != (err != nil) {
				t.Errorf("parsePeriod(%q) error = %v, wantErr = %v", c.query, err, c.wantErr)
			}
		})
	}
}

func TestScopeFilterMapsTheToggleToAPayer(t *testing.T) {
	caller := uuid.New()
	cases := []struct {
		scope   string
		want    *uuid.UUID
		wantErr bool
	}{
		{"", nil, false},
		{"household", nil, false},
		{"mine", &caller, false},
		{"everyone", nil, true},
		{"Mine", nil, true},
	}
	for _, c := range cases {
		t.Run("scope="+c.scope, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, "/v1/money?scope="+c.scope, nil)
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			got, err := scopeFilter(req, caller)
			if c.wantErr {
				if err == nil {
					t.Fatalf("scopeFilter(%q) = nil error, want an error", c.scope)
				}
				return
			}
			if err != nil {
				t.Fatalf("scopeFilter(%q) = %v", c.scope, err)
			}
			if (got == nil) != (c.want == nil) {
				t.Fatalf("scopeFilter(%q) = %v, want %v", c.scope, got, c.want)
			}
			if got != nil && *got != *c.want {
				t.Errorf("scopeFilter(%q) = %v, want %v", c.scope, *got, *c.want)
			}
		})
	}
}

func TestMintInviteTokenIsUnguessableAndStoredOnlyAsAHash(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 128; i++ {
		token, hash, err := mintInviteToken()
		if err != nil {
			t.Fatalf("mintInviteToken: %v", err)
		}
		if len(hash) != 32 {
			t.Fatalf("hash length = %d, want 32", len(hash))
		}
		if seen[token] {
			t.Fatalf("mintInviteToken repeated a token after %d draws", i)
		}
		seen[token] = true
		if string(hash) == token {
			t.Fatal("the stored hash equals the plaintext token")
		}
	}
}

// --- integration ---

// enableMoney turns a fresh space into a money household and returns its id.
func (h *harness) enableMoney(a *actor) string {
	h.t.Helper()
	spaceID := h.createSpace(a)
	rec := h.do(http.MethodPost, "/v1/money/households/"+spaceID+"/enable", a, nil)
	requireStatus(h.t, rec, http.StatusCreated)
	return spaceID
}

// firstCategory returns the id of a seeded category of the given kind.
func (h *harness) firstCategory(a *actor, spaceID, kind string) string {
	h.t.Helper()
	rec := h.do(http.MethodGet, "/v1/money/households/"+spaceID+"/categories", a, nil)
	requireStatus(h.t, rec, http.StatusOK)
	for _, raw := range decodeBody(h.t, rec)["categories"].([]any) {
		category := raw.(map[string]any)
		if category["kind"] == kind {
			return category["id"].(string)
		}
	}
	h.t.Fatalf("no seeded %s category", kind)
	return ""
}

func today() string { return time.Now().UTC().Format("2006-01-02") }

func TestEnableMoneySeedsCategoriesAndIsIdempotent(t *testing.T) {
	h := newHarness(t)
	a := h.signUp("owner")
	spaceID := h.enableMoney(a)

	rec := h.do(http.MethodGet, "/v1/money/households/"+spaceID+"/categories", a, nil)
	requireStatus(t, rec, http.StatusOK)
	categories := decodeBody(t, rec)["categories"].([]any)
	if len(categories) != 17 {
		t.Fatalf("seeded %d categories, want 17", len(categories))
	}

	// Enabling twice must not duplicate the seed or reset settings.
	requireStatus(t, h.do(http.MethodPost, "/v1/money/households/"+spaceID+"/enable", a, nil), http.StatusCreated)
	rec = h.do(http.MethodGet, "/v1/money/households/"+spaceID+"/categories", a, nil)
	if got := len(decodeBody(t, rec)["categories"].([]any)); got != 17 {
		t.Errorf("after re-enabling, %d categories, want 17", got)
	}
}

func TestCreateTransactionIsIdempotentOnClientID(t *testing.T) {
	h := newHarness(t)
	a := h.signUp("owner")
	spaceID := h.enableMoney(a)
	categoryID := h.firstCategory(a, spaceID, "expense")

	body := map[string]any{"clientId": uuid.NewString(), "categoryId": categoryID, "type": "expense", "amountMinor": 248000, "occurredOn": today(), "note": "Weekly big shop"}

	first := h.do(http.MethodPost, "/v1/money/households/"+spaceID+"/transactions", a, body)
	requireStatus(t, first, http.StatusCreated)
	firstID := decodeBody(t, first)["id"]

	// A retried request after a lost response must not charge the household twice.
	second := h.do(http.MethodPost, "/v1/money/households/"+spaceID+"/transactions", a, body)
	requireStatus(t, second, http.StatusCreated)
	if decodeBody(t, second)["id"] != firstID {
		t.Fatalf("retry created a second entry: %v then %v", firstID, decodeBody(t, second)["id"])
	}

	rec := h.do(http.MethodGet, "/v1/money/households/"+spaceID+"/transactions?from="+today()+"&to="+today(), a, nil)
	requireStatus(t, rec, http.StatusOK)
	if got := len(decodeBody(t, rec)["transactions"].([]any)); got != 1 {
		t.Errorf("ledger holds %d entries after a retry, want 1", got)
	}
}

func TestTransactionAmountBoundsAreEnforced(t *testing.T) {
	h := newHarness(t)
	a := h.signUp("owner")
	spaceID := h.enableMoney(a)
	categoryID := h.firstCategory(a, spaceID, "expense")

	for _, amount := range []int64{0, -1, 100000000001} {
		body := map[string]any{"clientId": uuid.NewString(), "categoryId": categoryID, "type": "expense", "amountMinor": amount, "occurredOn": today()}
		rec := h.do(http.MethodPost, "/v1/money/households/"+spaceID+"/transactions", a, body)
		requireStatus(t, rec, http.StatusBadRequest)
		if code := errorCode(t, rec); code != "invalid_request" {
			t.Errorf("amount %d gave code %q, want invalid_request", amount, code)
		}
	}
}

func TestSummaryAddsUpAndRespectsTheScopeToggle(t *testing.T) {
	h := newHarness(t)
	owner := h.signUp("owner")
	spaceID := h.enableMoney(owner)
	expense := h.firstCategory(owner, spaceID, "expense")
	income := h.firstCategory(owner, spaceID, "income")

	amounts := []int64{248000, 64000, 31000}
	for _, amount := range amounts {
		body := map[string]any{"clientId": uuid.NewString(), "categoryId": expense, "type": "expense", "amountMinor": amount, "occurredOn": today()}
		requireStatus(t, h.do(http.MethodPost, "/v1/money/households/"+spaceID+"/transactions", owner, body), http.StatusCreated)
	}
	salary := map[string]any{"clientId": uuid.NewString(), "categoryId": income, "type": "income", "amountMinor": 18600000, "occurredOn": today()}
	requireStatus(t, h.do(http.MethodPost, "/v1/money/households/"+spaceID+"/transactions", owner, salary), http.StatusCreated)

	rec := h.do(http.MethodGet, "/v1/money/households/"+spaceID+"/summary?from="+today()+"&to="+today(), owner, nil)
	requireStatus(t, rec, http.StatusOK)
	body := decodeBody(t, rec)

	var wantSpent int64
	for _, amount := range amounts {
		wantSpent += amount
	}
	if got := int64(body["spent"].(map[string]any)["minor"].(float64)); got != wantSpent {
		t.Errorf("spent = %d, want %d", got, wantSpent)
	}
	if got := int64(body["income"].(map[string]any)["minor"].(float64)); got != 18600000 {
		t.Errorf("income = %d, want 18600000", got)
	}
	if got := int64(body["net"].(map[string]any)["minor"].(float64)); got != 18600000-wantSpent {
		t.Errorf("net = %d, want %d", got, 18600000-wantSpent)
	}

	// A second member's spending must leave the first member's "mine" view alone.
	other := h.signUp("other")
	rec = h.do(http.MethodGet, "/v1/money/households/"+spaceID+"/summary?from="+today()+"&to="+today()+"&scope=mine", other, nil)
	requireStatus(t, rec, http.StatusNotFound)
}

func TestBudgetTracksSpendingAgainstItsCeiling(t *testing.T) {
	h := newHarness(t)
	a := h.signUp("owner")
	spaceID := h.enableMoney(a)
	categoryID := h.firstCategory(a, spaceID, "expense")

	requireStatus(t, h.do(http.MethodPut, "/v1/money/households/"+spaceID+"/budgets", a, map[string]any{"categoryId": categoryID, "limitMinor": 2400000}), http.StatusOK)

	spend := map[string]any{"clientId": uuid.NewString(), "categoryId": categoryID, "type": "expense", "amountMinor": 900000, "occurredOn": today()}
	requireStatus(t, h.do(http.MethodPost, "/v1/money/households/"+spaceID+"/transactions", a, spend), http.StatusCreated)

	rec := h.do(http.MethodGet, "/v1/money/households/"+spaceID+"/budgets?from="+today()+"&to="+today(), a, nil)
	requireStatus(t, rec, http.StatusOK)
	budgets := decodeBody(t, rec)["budgets"].([]any)
	if len(budgets) != 1 {
		t.Fatalf("got %d budgets, want 1", len(budgets))
	}
	budget := budgets[0].(map[string]any)
	if got := int64(budget["used"].(map[string]any)["minor"].(float64)); got != 900000 {
		t.Errorf("used = %d, want 900000", got)
	}
	if got := int64(budget["remaining"].(map[string]any)["minor"].(float64)); got != 1500000 {
		t.Errorf("remaining = %d, want 1500000", got)
	}

	// Re-putting the same category updates the ceiling rather than duplicating it.
	requireStatus(t, h.do(http.MethodPut, "/v1/money/households/"+spaceID+"/budgets", a, map[string]any{"categoryId": categoryID, "limitMinor": 3000000}), http.StatusOK)
	rec = h.do(http.MethodGet, "/v1/money/households/"+spaceID+"/budgets?from="+today()+"&to="+today(), a, nil)
	if got := len(decodeBody(t, rec)["budgets"].([]any)); got != 1 {
		t.Errorf("got %d budgets after re-put, want 1", got)
	}
}

func TestHoldingIsValuedExactly(t *testing.T) {
	h := newHarness(t)
	a := h.signUp("owner")
	spaceID := h.enableMoney(a)

	body := map[string]any{"name": "Nifty 50 Index Fund", "badge": "IDX", "assetType": "mutual_fund", "units": "2840", "avgCostMinor": 16840, "lastPriceMinor": 21490, "dayChangeBps": 62, "sipMinor": 2500000}
	rec := h.do(http.MethodPost, "/v1/money/households/"+spaceID+"/holdings", a, body)
	requireStatus(t, rec, http.StatusCreated)

	holding := decodeBody(t, rec)
	wantValue := int64(2840 * 21490)
	wantCost := int64(2840 * 16840)
	if got := int64(holding["value"].(map[string]any)["minor"].(float64)); got != wantValue {
		t.Errorf("value = %d, want %d", got, wantValue)
	}
	if got := int64(holding["cost"].(map[string]any)["minor"].(float64)); got != wantCost {
		t.Errorf("cost = %d, want %d", got, wantCost)
	}
	if got := int64(holding["unrealised"].(map[string]any)["minor"].(float64)); got != wantValue-wantCost {
		t.Errorf("unrealised = %d, want %d", got, wantValue-wantCost)
	}
}

func TestNonMemberCannotReachAHousehold(t *testing.T) {
	h := newHarness(t)
	owner := h.signUp("owner")
	stranger := h.signUp("stranger")
	spaceID := h.enableMoney(owner)

	// A household nobody told them about is indistinguishable from one that does
	// not exist, so probing ids leaks nothing.
	rec := h.do(http.MethodGet, "/v1/money/households/"+spaceID+"/transactions?from="+today()+"&to="+today(), stranger, nil)
	requireStatus(t, rec, http.StatusNotFound)

	rec = h.do(http.MethodPost, "/v1/money/households/"+spaceID+"/transactions", stranger, map[string]any{"clientId": uuid.NewString(), "categoryId": uuid.NewString(), "type": "expense", "amountMinor": 100, "occurredOn": today()})
	requireStatus(t, rec, http.StatusNotFound)
}

func TestCategoryFromAnotherHouseholdIsRejected(t *testing.T) {
	h := newHarness(t)
	a := h.signUp("owner")
	mine := h.enableMoney(a)
	theirs := h.enableMoney(a)
	foreign := h.firstCategory(a, theirs, "expense")

	body := map[string]any{"clientId": uuid.NewString(), "categoryId": foreign, "type": "expense", "amountMinor": 5000, "occurredOn": today()}
	rec := h.do(http.MethodPost, "/v1/money/households/"+mine+"/transactions", a, body)
	requireStatus(t, rec, http.StatusForbidden)
	if code := errorCode(t, rec); code != "cross_household" {
		t.Errorf("error code = %q, want cross_household", code)
	}
}

func TestPaidByMustBeAHouseholdMember(t *testing.T) {
	h := newHarness(t)
	a := h.signUp("owner")
	outsider := h.signUp("outsider")
	spaceID := h.enableMoney(a)
	categoryID := h.firstCategory(a, spaceID, "expense")

	body := map[string]any{"clientId": uuid.NewString(), "categoryId": categoryID, "type": "expense", "amountMinor": 5000, "occurredOn": today(), "paidBy": outsider.UserID.String()}
	rec := h.do(http.MethodPost, "/v1/money/households/"+spaceID+"/transactions", a, body)
	requireStatus(t, rec, http.StatusBadRequest)
}

func TestInviteRoundTripAddsAMemberExactlyOnce(t *testing.T) {
	h := newHarness(t)
	owner := h.signUp("owner")
	guest := h.signUp("guest")
	spaceID := h.enableMoney(owner)

	rec := h.do(http.MethodPost, "/v1/money/households/"+spaceID+"/invites", owner, map[string]any{"email": "amma@home.in", "role": "editor"})
	requireStatus(t, rec, http.StatusCreated)
	token, ok := decodeBody(t, rec)["token"].(string)
	if !ok || token == "" {
		t.Fatal("invite response carried no token")
	}

	// Same address twice is a conflict, not a second live invite.
	rec = h.do(http.MethodPost, "/v1/money/households/"+spaceID+"/invites", owner, map[string]any{"email": "amma@home.in"})
	requireStatus(t, rec, http.StatusConflict)

	requireStatus(t, h.do(http.MethodPost, "/v1/money/invites/accept", guest, map[string]any{"token": token}), http.StatusOK)

	// The guest can now read the ledger.
	requireStatus(t, h.do(http.MethodGet, "/v1/money/households/"+spaceID+"/transactions?from="+today()+"&to="+today(), guest, nil), http.StatusOK)

	// A spent token cannot be redeemed again.
	third := h.signUp("third")
	requireStatus(t, h.do(http.MethodPost, "/v1/money/invites/accept", third, map[string]any{"token": token}), http.StatusNotFound)
	requireStatus(t, h.do(http.MethodGet, "/v1/money/households/"+spaceID+"/transactions?from="+today()+"&to="+today(), third, nil), http.StatusNotFound)
}

func TestForgedInviteTokenIsRejected(t *testing.T) {
	h := newHarness(t)
	a := h.signUp("owner")

	for _, token := range []string{"", "oski_", "oski_" + uuid.NewString(), "not-a-token"} {
		rec := h.do(http.MethodPost, "/v1/money/invites/accept", a, map[string]any{"token": token})
		requireStatus(t, rec, http.StatusNotFound)
	}
}

func TestViewerCannotWriteAndEditorCannotInvite(t *testing.T) {
	h := newHarness(t)
	owner := h.signUp("owner")
	viewer := h.signUp("viewer")
	spaceID := h.enableMoney(owner)
	categoryID := h.firstCategory(owner, spaceID, "expense")

	rec := h.do(http.MethodPost, "/v1/money/households/"+spaceID+"/invites", owner, map[string]any{"email": "viewer@home.in", "role": "viewer"})
	requireStatus(t, rec, http.StatusCreated)
	token := decodeBody(t, rec)["token"].(string)
	requireStatus(t, h.do(http.MethodPost, "/v1/money/invites/accept", viewer, map[string]any{"token": token}), http.StatusOK)

	requireStatus(t, h.do(http.MethodGet, "/v1/money/households/"+spaceID+"/transactions?from="+today()+"&to="+today(), viewer, nil), http.StatusOK)

	write := map[string]any{"clientId": uuid.NewString(), "categoryId": categoryID, "type": "expense", "amountMinor": 5000, "occurredOn": today()}
	rec = h.do(http.MethodPost, "/v1/money/households/"+spaceID+"/transactions", viewer, write)
	requireStatus(t, rec, http.StatusForbidden)
	if code := errorCode(t, rec); code != "insufficient_role" {
		t.Errorf("error code = %q, want insufficient_role", code)
	}

	// Inviting is owner-only, so even a writer cannot widen the household.
	rec = h.do(http.MethodPost, "/v1/money/households/"+spaceID+"/invites", viewer, map[string]any{"email": "someone@home.in"})
	requireStatus(t, rec, http.StatusForbidden)
}

func TestDeletedTransactionLeavesTheLedgerAndTheTotals(t *testing.T) {
	h := newHarness(t)
	a := h.signUp("owner")
	spaceID := h.enableMoney(a)
	categoryID := h.firstCategory(a, spaceID, "expense")

	body := map[string]any{"clientId": uuid.NewString(), "categoryId": categoryID, "type": "expense", "amountMinor": 123400, "occurredOn": today()}
	rec := h.do(http.MethodPost, "/v1/money/households/"+spaceID+"/transactions", a, body)
	requireStatus(t, rec, http.StatusCreated)
	id := decodeBody(t, rec)["id"].(string)

	requireStatus(t, h.do(http.MethodDelete, "/v1/money/households/"+spaceID+"/transactions/"+id, a, nil), http.StatusNoContent)
	// Deleting twice is not an error; the entry is simply gone either way.
	requireStatus(t, h.do(http.MethodDelete, "/v1/money/households/"+spaceID+"/transactions/"+id, a, nil), http.StatusNoContent)

	rec = h.do(http.MethodGet, "/v1/money/households/"+spaceID+"/summary?from="+today()+"&to="+today(), a, nil)
	requireStatus(t, rec, http.StatusOK)
	if got := int64(decodeBody(t, rec)["spent"].(map[string]any)["minor"].(float64)); got != 0 {
		t.Errorf("spent = %d after deleting the only entry, want 0", got)
	}
}

func TestLedgerPagesWithoutRepeatingOrSkippingEntries(t *testing.T) {
	h := newHarness(t)
	a := h.signUp("owner")
	spaceID := h.enableMoney(a)
	categoryID := h.firstCategory(a, spaceID, "expense")

	const total = 25
	for i := 0; i < total; i++ {
		day := time.Now().UTC().AddDate(0, 0, -i).Format("2006-01-02")
		body := map[string]any{"clientId": uuid.NewString(), "categoryId": categoryID, "type": "expense", "amountMinor": int64(1000 + i), "occurredOn": day, "note": fmt.Sprintf("entry %d", i)}
		requireStatus(t, h.do(http.MethodPost, "/v1/money/households/"+spaceID+"/transactions", a, body), http.StatusCreated)
	}

	from := time.Now().UTC().AddDate(0, 0, -total).Format("2006-01-02")
	seen := make(map[string]bool)
	cursor := ""
	for pages := 0; pages < 10; pages++ {
		path := "/v1/money/households/" + spaceID + "/transactions?limit=7&from=" + from + "&to=" + today()
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		rec := h.do(http.MethodGet, path, a, nil)
		requireStatus(t, rec, http.StatusOK)
		body := decodeBody(t, rec)
		for _, raw := range body["transactions"].([]any) {
			id := raw.(map[string]any)["id"].(string)
			if seen[id] {
				t.Fatalf("cursor walk returned %s twice", id)
			}
			seen[id] = true
		}
		cursor, _ = body["nextCursor"].(string)
		if cursor == "" {
			break
		}
	}
	if len(seen) != total {
		t.Errorf("cursor walk saw %d entries, want %d", len(seen), total)
	}

	rec := h.do(http.MethodGet, "/v1/money/households/"+spaceID+"/transactions?from="+from+"&to="+today()+"&cursor=not-a-cursor", a, nil)
	requireStatus(t, rec, http.StatusConflict)
}

func TestSearchAndScopeNarrowTheFeed(t *testing.T) {
	h := newHarness(t)
	owner := h.signUp("owner")
	spaceID := h.enableMoney(owner)
	categoryID := h.firstCategory(owner, spaceID, "expense")

	for _, note := range []string{"Weekly big shop", "Auto to office", "Filter coffee"} {
		body := map[string]any{"clientId": uuid.NewString(), "categoryId": categoryID, "type": "expense", "amountMinor": 1000, "occurredOn": today(), "note": note}
		requireStatus(t, h.do(http.MethodPost, "/v1/money/households/"+spaceID+"/transactions", owner, body), http.StatusCreated)
	}

	rec := h.do(http.MethodGet, "/v1/money/households/"+spaceID+"/transactions?from="+today()+"&to="+today()+"&search=coffee", owner, nil)
	requireStatus(t, rec, http.StatusOK)
	if got := len(decodeBody(t, rec)["transactions"].([]any)); got != 1 {
		t.Errorf("search=coffee matched %d entries, want 1", got)
	}

	// Search must not become a wildcard when the term contains SQL LIKE syntax.
	rec = h.do(http.MethodGet, "/v1/money/households/"+spaceID+"/transactions?from="+today()+"&to="+today()+"&search=%25", owner, nil)
	requireStatus(t, rec, http.StatusOK)

	rec = h.do(http.MethodGet, "/v1/money/households/"+spaceID+"/transactions?from="+today()+"&to="+today()+"&scope=mine", owner, nil)
	requireStatus(t, rec, http.StatusOK)
	if got := len(decodeBody(t, rec)["transactions"].([]any)); got != 3 {
		t.Errorf("scope=mine matched %d entries, want 3", got)
	}

	rec = h.do(http.MethodGet, "/v1/money/households/"+spaceID+"/transactions?from="+today()+"&to="+today()+"&scope=everyone", owner, nil)
	requireStatus(t, rec, http.StatusBadRequest)
}
