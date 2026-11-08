package home

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

// fakeModel answers every Messages call with one text block carrying reply, and records the prompt it saw.
func fakeModel(t *testing.T, reply string, stop string) (*Vision, *string) {
	t.Helper()
	var prompt string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Model    string `json:"model"`
			Messages []struct {
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&request)
		if request.Model != "claude-sonnet-5" {
			t.Errorf("estimate must use Sonnet, got %q", request.Model)
		}
		if len(request.Messages) > 0 && len(request.Messages[0].Content) > 0 {
			prompt = request.Messages[0].Content[0].Text
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "msg_test", "type": "message", "role": "assistant", "model": request.Model,
			"content":     []map[string]any{{"type": "text", "text": reply}},
			"stop_reason": stop,
			"usage":       map[string]any{"input_tokens": 100, "output_tokens": 50},
		})
	}))
	t.Cleanup(server.Close)
	return &Vision{client: anthropic.NewClient(option.WithAPIKey("test-token-not-real"), option.WithBaseURL(server.URL), option.WithMaxRetries(0))}, &prompt
}

func TestEstimateDishKeepsOnlyRowsTheKitchenCanCount(t *testing.T) {
	reply := `{"kcal":480,"proteinG":14,"carbsG":70,"fatG":15,"ingredients":[{"name":"paneer","qty":"200 g"},{"name":"Cream","qty":"a splash"},{"name":"Tomato","qty":"3 pcs"},{"name":"","qty":"1 kg"}]}`
	vision, prompt := fakeModel(t, reply, "end_turn")
	estimate, err := vision.EstimateDish(context.Background(), "Paneer Butter Masala")
	if err != nil {
		t.Fatal(err)
	}
	if estimate.Kcal != 480 || estimate.ProteinG != 14 || estimate.Serves != 2 {
		t.Fatalf("numbers: %+v", estimate)
	}
	if len(estimate.Ingredients) != 2 || estimate.Ingredients[0].Name != "Paneer" || estimate.Ingredients[1].Qty != "3 pcs" {
		t.Fatalf("ingredients should be the two countable rows, title-cased: %+v", estimate.Ingredients)
	}
	if !strings.Contains(*prompt, `"Paneer Butter Masala"`) || !strings.Contains(*prompt, "ONE normal home serving") {
		t.Fatalf("prompt did not carry the dish: %s", *prompt)
	}
}

func TestEstimateDishRefusesWhatAMealWouldRefuse(t *testing.T) {
	cases := map[string]struct{ reply, stop string }{
		"calories out of range": {`{"kcal":9000,"proteinG":1,"carbsG":1,"fatG":1,"ingredients":[]}`, "end_turn"},
		"negative grams":        {`{"kcal":400,"proteinG":-3,"carbsG":1,"fatG":1,"ingredients":[]}`, "end_turn"},
		"not json":              {`sure! here is the dish`, "end_turn"},
		"refusal":               {`{}`, "refusal"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			vision, _ := fakeModel(t, tc.reply, tc.stop)
			if _, err := vision.EstimateDish(context.Background(), "Dal"); err != errEstimateFailed {
				t.Fatalf("expected estimate_failed, got %v", err)
			}
		})
	}
}

func TestEstimateRouteNeedsAKeyAndAName(t *testing.T) {
	server, username, password := testServer(t)
	if status, _ := call(t, server, http.MethodPost, "/v1/dishes/estimate", "", map[string]any{"name": "Dal"}); status != http.StatusUnauthorized {
		t.Fatalf("without a token: %d", status)
	}
	token := signIn(t, server, username, password)
	status, body := call(t, server, http.MethodPost, "/v1/dishes/estimate", token, map[string]any{"name": "Dal"})
	if status != http.StatusServiceUnavailable || body["error"].(map[string]any)["code"] != "estimate_unavailable" {
		t.Fatalf("without a key: %d %v", status, body)
	}
}

func TestEstimateRouteValidatesTheNameBeforeTheModel(t *testing.T) {
	store := testStore(t)
	vision, _ := fakeModel(t, `{"kcal":80,"proteinG":2,"carbsG":10,"fatG":3,"ingredients":[{"name":"Milk","qty":"200 ml"}]}`, "end_turn")
	server := httptest.NewServer(newServer(store, Config{AllowLocalhost: true}, vision))
	t.Cleanup(server.Close)
	username, password := testUser(t, store)
	token := signIn(t, server, username, password)
	for name, want := range map[string]int{"": http.StatusBadRequest, strings.Repeat("x", 81): http.StatusBadRequest, "  Masala   Chai ": http.StatusOK} {
		if status, body := call(t, server, http.MethodPost, "/v1/dishes/estimate", token, map[string]any{"name": name}); status != want {
			t.Fatalf("name %q: %d %v", name, status, body)
		}
	}
	status, body := call(t, server, http.MethodPost, "/v1/dishes/estimate", token, map[string]any{"name": "Masala Chai"})
	if status != http.StatusOK || body["kcal"].(float64) != 80 || body["serves"].(float64) != 2 || len(body["ingredients"].([]any)) != 1 {
		t.Fatalf("estimate: %d %v", status, body)
	}
}
