package home

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// testMonth picks a month far in the future and alone in its year, so parallel test runs on the shared database never share a month.
func testMonth() time.Time {
	return time.Date(2200+rand.IntN(700), time.Month(1+rand.IntN(10)), 1, 0, 0, 0, 0, time.UTC)
}

func ym(month time.Time) string { return month.Format("2006-01") }

func rawCall(t *testing.T, server *httptest.Server, method, path, token string, body []byte, contentType string) *http.Response {
	t.Helper()
	request, _ := http.NewRequest(method, server.URL+path, bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	t.Cleanup(func() { response.Body.Close() })
	return response
}

func fixedItemsIn(t *testing.T, server *httptest.Server, token, month string) []map[string]any {
	t.Helper()
	status, body := call(t, server, http.MethodGet, "/v1/fixed?month="+month, token, nil)
	if status != http.StatusOK {
		t.Fatalf("list %s: %d %v", month, status, body)
	}
	months := body["months"].([]any)
	if len(months) != 1 || months[0].(map[string]any)["month"] != month {
		t.Fatalf("expected exactly %s back, got %v", month, months)
	}
	items := months[0].(map[string]any)["items"].([]any)
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		out = append(out, item.(map[string]any))
	}
	return out
}

func TestFixedRoutesNeedASession(t *testing.T) {
	server, _, _ := testServer(t)
	for _, route := range [][2]string{{http.MethodGet, "/v1/fixed?month=2030-01"}, {http.MethodPost, "/v1/fixed"}, {http.MethodPut, "/v1/fixed/" + testUUID}, {http.MethodDelete, "/v1/fixed/" + testUUID}, {http.MethodPut, "/v1/fixed/" + testUUID + "/payments/2030-01"}, {http.MethodGet, "/v1/fixed/" + testUUID + "/payments/2030-01/proof"}} {
		if status, _ := call(t, server, route[0], route[1], "", map[string]any{}); status != http.StatusUnauthorized {
			t.Fatalf("%s %s without a token: %d", route[0], route[1], status)
		}
	}
}

func TestFixedItemValidation(t *testing.T) {
	server, username, password := testServer(t)
	token := signIn(t, server, username, password)
	expense := categoryOfKind(t, server, token, "expense")
	income := categoryOfKind(t, server, token, "income")
	_, me := call(t, server, http.MethodGet, "/v1/me", token, nil)
	myID := me["id"].(string)
	good := func() map[string]any {
		return map[string]any{"name": "Rent", "kind": "expense", "amountMinor": 2500000, "categoryId": expense, "dueDay": 5, "startsOn": "2030-01"}
	}
	cases := map[string]func(map[string]any){
		"empty name":                    func(b map[string]any) { b["name"] = "  " },
		"long name":                     func(b map[string]any) { b["name"] = strings.Repeat("x", 61) },
		"unknown kind":                  func(b map[string]any) { b["kind"] = "loan" },
		"zero amount":                   func(b map[string]any) { b["amountMinor"] = 0 },
		"income without an owner":       func(b map[string]any) { b["kind"] = "income"; delete(b, "categoryId") },
		"investment with a category":    func(b map[string]any) { b["kind"] = "investment"; b["ownerId"] = myID },
		"income category on an expense": func(b map[string]any) { b["categoryId"] = income },
		"due day 32":                    func(b map[string]any) { b["dueDay"] = 32 },
		"start month not YYYY-MM":       func(b map[string]any) { b["startsOn"] = "2030-1" },
		"owner who is not a member":     func(b map[string]any) { b["ownerId"] = testUUID },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			body := good()
			mutate(body)
			if status, reply := call(t, server, http.MethodPost, "/v1/fixed", token, body); status != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d %v", status, reply)
			}
		})
	}
	if status, reply := call(t, server, http.MethodGet, "/v1/fixed?from=2030-03&to=2030-01", token, nil); status != http.StatusBadRequest {
		t.Fatalf("backwards range: %d %v", status, reply)
	}
	if status, reply := call(t, server, http.MethodGet, "/v1/fixed?from=2030-01&to=2031-02", token, nil); status != http.StatusBadRequest {
		t.Fatalf("14-month range: %d %v", status, reply)
	}
	if status, reply := call(t, server, http.MethodGet, "/v1/fixed?month=2030-13", token, nil); status != http.StatusBadRequest {
		t.Fatalf("month 13: %d %v", status, reply)
	}
}

func TestFixedItemShowsEveryMonthUntilArchivedAndKeepsPaidHistory(t *testing.T) {
	server, username, password := testServer(t)
	token := signIn(t, server, username, password)
	expense := categoryOfKind(t, server, token, "expense")
	_, me := call(t, server, http.MethodGet, "/v1/me", token, nil)
	myID := me["id"].(string)
	start := testMonth()
	m0, m1, m2 := ym(start), ym(start.AddDate(0, 1, 0)), ym(start.AddDate(0, 2, 0))

	status, rent := call(t, server, http.MethodPost, "/v1/fixed", token, map[string]any{"name": "  Rent ", "kind": "expense", "amountMinor": 2500000, "categoryId": expense, "dueDay": 5, "startsOn": m1})
	if status != http.StatusCreated || rent["name"] != "Rent" || rent["startsOn"] != m1 || rent["endsOn"] != nil || rent["ownerId"] != nil {
		t.Fatalf("create: %d %v", status, rent)
	}
	rentID := rent["id"].(string)
	status, salary := call(t, server, http.MethodPost, "/v1/fixed", token, map[string]any{"name": "Salary", "kind": "income", "amountMinor": 14000000, "ownerId": myID, "startsOn": m1})
	if status != http.StatusCreated {
		t.Fatalf("create salary: %d %v", status, salary)
	}

	if items := fixedItemsIn(t, server, token, m0); len(items) != 0 {
		t.Fatalf("the month before the start should be empty, got %v", items)
	}
	items := fixedItemsIn(t, server, token, m2)
	if len(items) != 2 || items[0]["name"] != "Rent" || items[1]["name"] != "Salary" || items[0]["payment"] != nil {
		t.Fatalf("two months on, expenses first, nothing paid: %v", items)
	}

	status, paid := call(t, server, http.MethodPut, "/v1/fixed/"+rentID+"/payments/"+m1, token, map[string]any{})
	if status != http.StatusOK || paid["amountMinor"].(float64) != 2500000 || paid["paidBy"] != myID || paid["proofType"] != "" || paid["month"] != m1 {
		t.Fatalf("tick with an empty body takes the item's amount and me as payer: %d %v", status, paid)
	}
	if paid["paidOn"].(string) != time.Now().UTC().Format("2006-01-02") {
		t.Fatalf("tick without a date is today: %v", paid["paidOn"])
	}
	status, again := call(t, server, http.MethodPut, "/v1/fixed/"+rentID+"/payments/"+m1, token, map[string]any{"amountMinor": 2600000, "paidOn": m1 + "-03", "note": "late fee"})
	if status != http.StatusOK || again["id"] != paid["id"] || again["amountMinor"].(float64) != 2600000 || again["note"] != "late fee" || again["paidOn"] != m1+"-03" {
		t.Fatalf("second tick updates the same payment: %d %v", status, again)
	}
	if status, reply := call(t, server, http.MethodPut, "/v1/fixed/"+rentID+"/payments/"+m1, token, map[string]any{"paidBy": testUUID}); status != http.StatusBadRequest {
		t.Fatalf("payer who is not a member: %d %v", status, reply)
	}

	status, edited := call(t, server, http.MethodPut, "/v1/fixed/"+rentID, token, map[string]any{"name": "Rent", "kind": "expense", "amountMinor": 2700000, "categoryId": expense, "dueDay": 7, "startsOn": m1})
	if status != http.StatusOK || edited["amountMinor"].(float64) != 2700000 || edited["dueDay"].(float64) != 7 {
		t.Fatalf("edit: %d %v", status, edited)
	}
	items = fixedItemsIn(t, server, token, m1)
	if items[0]["amountMinor"].(float64) != 2700000 || items[0]["payment"].(map[string]any)["amountMinor"].(float64) != 2600000 {
		t.Fatalf("the item shows the new amount, the paid month keeps what was paid: %v", items[0])
	}

	if status, _ := call(t, server, http.MethodDelete, "/v1/fixed/"+rentID+"?month="+m2, token, nil); status != http.StatusNoContent {
		t.Fatalf("archive from an unpaid month: %d", status)
	}
	if items := fixedItemsIn(t, server, token, m2); len(items) != 1 || items[0]["name"] != "Salary" {
		t.Fatalf("archived from %s, rent should be gone there: %v", m2, items)
	}
	items = fixedItemsIn(t, server, token, m1)
	if len(items) != 2 || items[0]["name"] != "Rent" || items[0]["endsOn"] != m1 || items[0]["payment"] == nil {
		t.Fatalf("the paid month keeps rent with its payment and an end: %v", items)
	}

	salaryID := salary["id"].(string)
	if status, _ := call(t, server, http.MethodDelete, "/v1/fixed/"+salaryID+"?month="+m2, token, nil); status != http.StatusNoContent {
		t.Fatalf("delete never-paid item: %d", status)
	}
	if items := fixedItemsIn(t, server, token, m1); len(items) != 1 {
		t.Fatalf("a never-paid item is deleted outright, even from earlier months: %v", items)
	}
	if status, _ := call(t, server, http.MethodDelete, "/v1/fixed/"+salaryID, token, nil); status != http.StatusNotFound {
		t.Fatalf("deleting twice: %d", status)
	}

	status, body := call(t, server, http.MethodGet, fmt.Sprintf("/v1/fixed?from=%s&to=%s", m0, m2), token, nil)
	months := body["months"].([]any)
	if status != http.StatusOK || len(months) != 3 || months[0].(map[string]any)["month"] != m0 || len(months[1].(map[string]any)["items"].([]any)) != 1 {
		t.Fatalf("range read: %d %v", status, body)
	}
	if _, ok := body["holdingsSipMinor"].(float64); !ok {
		t.Fatalf("range read carries the holdings SIP total: %v", body)
	}
}

func TestFixedProofFollowsThePayment(t *testing.T) {
	server, username, password := testServer(t)
	token := signIn(t, server, username, password)
	month := ym(testMonth())
	status, item := call(t, server, http.MethodPost, "/v1/fixed", token, map[string]any{"name": "Electricity", "kind": "expense", "amountMinor": 250000, "startsOn": month})
	if status != http.StatusCreated {
		t.Fatalf("create: %d %v", status, item)
	}
	id := item["id"].(string)
	proofPath := "/v1/fixed/" + id + "/payments/" + month + "/proof"
	pdf := []byte("%PDF-1.4 test bill " + strings.Repeat("x", 500))

	if status, reply := call(t, server, http.MethodPut, proofPath, token, map[string]any{"mediaType": "application/pdf", "data": base64.StdEncoding.EncodeToString(pdf)}); status != http.StatusNotFound {
		t.Fatalf("a proof needs a tick first: %d %v", status, reply)
	}
	if status, _ := call(t, server, http.MethodPut, "/v1/fixed/"+id+"/payments/"+month, token, map[string]any{}); status != http.StatusOK {
		t.Fatalf("tick: %d", status)
	}
	if status, reply := call(t, server, http.MethodPut, proofPath, token, map[string]any{"mediaType": "text/plain", "data": "aGk="}); status != http.StatusBadRequest {
		t.Fatalf("text proof: %d %v", status, reply)
	}
	tooBig := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, maxProofFileSize+1))
	if status, reply := call(t, server, http.MethodPut, proofPath, token, map[string]any{"mediaType": "image/jpeg", "data": tooBig}); status != http.StatusBadRequest {
		t.Fatalf("4 MB + 1: %d %v", status, reply)
	}
	if status, _ := call(t, server, http.MethodPut, proofPath, token, map[string]any{"mediaType": "application/pdf", "data": base64.StdEncoding.EncodeToString(pdf)}); status != http.StatusNoContent {
		t.Fatalf("attach: %d", status)
	}

	response := rawCall(t, server, http.MethodGet, proofPath, token, nil, "")
	got, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK || !bytes.Equal(got, pdf) || response.Header.Get("Content-Type") != "application/pdf" || !strings.Contains(response.Header.Get("Cache-Control"), "private") {
		t.Fatalf("read back: %d %q %q", response.StatusCode, response.Header.Get("Content-Type"), response.Header.Get("Cache-Control"))
	}
	items := fixedItemsIn(t, server, token, month)
	if items[0]["payment"].(map[string]any)["proofType"] != "application/pdf" {
		t.Fatalf("the month view says a proof is attached: %v", items[0])
	}

	if status, _ := call(t, server, http.MethodDelete, "/v1/fixed/"+id+"/payments/"+month, token, nil); status != http.StatusNoContent {
		t.Fatalf("untick: %d", status)
	}
	if response := rawCall(t, server, http.MethodGet, proofPath, token, nil, ""); response.StatusCode != http.StatusNotFound {
		t.Fatalf("the proof goes with the tick: %d", response.StatusCode)
	}
	if status, _ := call(t, server, http.MethodDelete, "/v1/fixed/"+id+"/payments/"+month, token, nil); status != http.StatusNotFound {
		t.Fatalf("unticking twice: %d", status)
	}
}
