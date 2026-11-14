package home

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func bodyFor(t *testing.T, server *httptest.Server, token, from, to string) map[string]any {
	t.Helper()
	status, body := call(t, server, http.MethodGet, "/v1/body?from="+from+"&to="+to, token, nil)
	if status != http.StatusOK {
		t.Fatalf("get body: %d %v", status, body)
	}
	return body
}

func TestBodyProfileRoundTripsAndRefusesBadValues(t *testing.T) {
	server, username, password := testServer(t)
	token := signIn(t, server, username, password)
	day := testDays(1)[0]

	fresh := bodyFor(t, server, token, day, day)
	profile := fresh["profile"].(map[string]any)
	if profile["weeklyG"].(float64) != 500 || profile["heightCm"] != nil || fresh["latestWeight"] != nil {
		t.Fatalf("defaults: %v", fresh)
	}

	status, saved := call(t, server, http.MethodPut, "/v1/body/profile", token, map[string]any{"heightCm": 176, "birthYear": 1992, "sex": "male", "goalWeightG": 72000, "goalFatX10": 180, "weeklyG": 500, "goalBy": "2027-04-05", "healthSync": true})
	if status != http.StatusOK || saved["heightCm"].(float64) != 176 || saved["healthSync"] != true || saved["goalFatX10"].(float64) != 180 || saved["goalBy"] != "2027-04-05" {
		t.Fatalf("save profile: %d %v", status, saved)
	}
	status, saved = call(t, server, http.MethodPut, "/v1/body/profile", token, map[string]any{"heightCm": 176, "weeklyG": 250})
	if status != http.StatusOK || saved["sex"] != nil || saved["goalBy"] != nil || saved["weeklyG"].(float64) != 250 {
		t.Fatalf("a field left out clears: %d %v", status, saved)
	}

	cases := map[string]map[string]any{
		"height":    {"heightCm": 99, "weeklyG": 500},
		"born":      {"birthYear": 2030, "weeklyG": 500},
		"sex":       {"sex": "other", "weeklyG": 500},
		"goal":      {"goalWeightG": 10000, "weeklyG": 500},
		"pace":      {"weeklyG": 50},
		"unknown":   {"weeklyG": 500, "extra": 1},
		"fat range": {"goalFatX10": 900, "weeklyG": 500},
		"goal date": {"goalBy": "5 April 2027", "weeklyG": 500},
		"no day":    {"goalBy": "2027-02-30", "weeklyG": 500},
	}
	for label, body := range cases {
		if status, _ := call(t, server, http.MethodPut, "/v1/body/profile", token, body); status != http.StatusBadRequest {
			t.Errorf("%s: expected 400, got %d", label, status)
		}
	}
}

func TestBodyDaysMergeAndAHandTypedWeightOutlivesAHealthSync(t *testing.T) {
	server, username, password := testServer(t)
	token := signIn(t, server, username, password)
	days := testDays(3)
	day1, day2, day3 := days[0], days[1], days[2]

	sync := map[string]any{"source": "health", "days": []any{
		map[string]any{"day": day1, "weightG": 76400, "fatX10": 220, "activeKcal": 530, "basalKcal": 1750, "exerciseMin": 42, "steps": 8420, "workouts": []any{map[string]any{"type": "walking", "startedAt": day1 + "T07:12:00+05:30", "minutes": 32, "kcal": 180}}},
		map[string]any{"day": day2, "activeKcal": 200, "steps": 3000},
	}}
	if status, body := call(t, server, http.MethodPut, "/v1/body/days", token, sync); status != http.StatusOK || body["saved"].(float64) != 2 {
		t.Fatalf("health sync: %d %v", status, body)
	}

	manual := map[string]any{"source": "manual", "days": []any{map[string]any{"day": day2, "weightG": 76000}}}
	if status, body := call(t, server, http.MethodPut, "/v1/body/days", token, manual); status != http.StatusOK {
		t.Fatalf("manual weight: %d %v", status, body)
	}

	again := map[string]any{"source": "health", "days": []any{map[string]any{"day": day2, "weightG": 77000, "fatX10": 230, "activeKcal": 410}}}
	if status, body := call(t, server, http.MethodPut, "/v1/body/days", token, again); status != http.StatusOK {
		t.Fatalf("second sync: %d %v", status, body)
	}

	got := bodyFor(t, server, token, day1, day3)
	listed := got["days"].([]any)
	if len(listed) != 2 {
		t.Fatalf("expected two days, got %v", listed)
	}
	newest := listed[0].(map[string]any)
	if newest["day"] != day2 || newest["weightG"].(float64) != 76000 || newest["weightSource"] != "manual" || newest["fatX10"] != nil {
		t.Fatalf("manual weight should survive the health sync: %v", newest)
	}
	if newest["activeKcal"].(float64) != 410 || newest["steps"].(float64) != 3000 {
		t.Fatalf("other fields merge field by field: %v", newest)
	}
	oldest := listed[1].(map[string]any)
	if oldest["weightSource"] != "health" || oldest["basalKcal"].(float64) != 1750 || len(oldest["workouts"].([]any)) != 1 {
		t.Fatalf("first day kept its sync: %v", oldest)
	}
	if got["latestWeight"].(map[string]any)["weightG"].(float64) != 76000 {
		t.Fatalf("latest weight should be the newest weighed day: %v", got["latestWeight"])
	}

	other, otherName, otherPassword := testServer(t)
	_ = other
	otherToken := signIn(t, server, otherName, otherPassword)
	if theirs := bodyFor(t, server, otherToken, day1, day3); len(theirs["days"].([]any)) != 0 || theirs["latestWeight"] != nil {
		t.Fatalf("another member must not see these days: %v", theirs)
	}

	bad := map[string]map[string]any{
		"source":   {"source": "watch", "days": []any{map[string]any{"day": day1}}},
		"twice":    {"source": "health", "days": []any{map[string]any{"day": day1}, map[string]any{"day": day1}}},
		"weight":   {"source": "manual", "days": []any{map[string]any{"day": day1, "weightG": 1000}}},
		"fat only": {"source": "manual", "days": []any{map[string]any{"day": day1, "fatX10": 200}}},
		"workout":  {"source": "health", "days": []any{map[string]any{"day": day1, "workouts": []any{map[string]any{"type": "", "minutes": 10, "kcal": 10}}}}},
		"empty":    {"source": "health", "days": []any{}},
	}
	for label, body := range bad {
		if status, _ := call(t, server, http.MethodPut, "/v1/body/days", token, body); status != http.StatusBadRequest {
			t.Errorf("%s: expected 400, got %d", label, status)
		}
	}
	if status, _ := call(t, server, http.MethodGet, "/v1/body?from=2020-01-01&to=2021-01-01", token, nil); status != http.StatusBadRequest {
		t.Errorf("a year-long read: expected 400, got %d", status)
	}
	if status, _ := call(t, server, http.MethodGet, "/v1/body?from="+day1+"&to="+day1, "", nil); status != http.StatusUnauthorized {
		t.Errorf("no token: expected 401, got %d", status)
	}
}
