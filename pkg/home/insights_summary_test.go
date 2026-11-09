package home

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestValidateFiguresKeepsFlatShortValuesAndSortsKeys(t *testing.T) {
	cases := []struct {
		name    string
		figures map[string]any
		ok      bool
	}{
		{"numbers, text and booleans pass", map[string]any{"spent": 39203.0, "range": "30 days", "overBudget": false}, true},
		{"the same figures in another order hash the same", map[string]any{"range": "30 days", "overBudget": false, "spent": 39203.0}, true},
		{"empty is refused", map[string]any{}, false},
		{"a nested object is refused", map[string]any{"days": map[string]any{"a": 1.0}}, false},
		{"a long string is refused", map[string]any{"note": strings.Repeat("x", maxSummaryValue+1)}, false},
		{"a long key is refused", map[string]any{strings.Repeat("k", maxSummaryKey+1): 1.0}, false},
	}
	var first, second string
	for _, tc := range cases {
		encoded, err := validateFigures(tc.figures)
		if (err == nil) != tc.ok {
			t.Errorf("%s: err = %v, want ok %v", tc.name, err, tc.ok)
			continue
		}
		if !tc.ok {
			var api apiError
			if !errors.As(err, &api) || api.status != 400 {
				t.Errorf("%s: want a 400, got %v", tc.name, err)
			}
			continue
		}
		switch tc.name {
		case "numbers, text and booleans pass":
			first = figuresHash(encoded)
		case "the same figures in another order hash the same":
			second = figuresHash(encoded)
		}
	}
	if first == "" || first != second {
		t.Errorf("hashes differ for the same figures: %q vs %q", first, second)
	}
}

func TestSummariseTrimsTheNoteAndFailsOnRefusal(t *testing.T) {
	vision, prompt := fakeModel(t, "  Your spend fell this month.\n\nKeep dinners at home twice more a week.  ", "end_turn")
	note, err := vision.Summarise(context.Background(), []byte(`{"spent":39203}`))
	if err != nil {
		t.Fatal(err)
	}
	if note != "Your spend fell this month. Keep dinners at home twice more a week." {
		t.Errorf("note = %q", note)
	}
	if fakeModelSeen != summaryModel {
		t.Errorf("model = %q, want %q", fakeModelSeen, summaryModel)
	}
	if !strings.Contains(*prompt, `{"spent":39203}`) {
		t.Errorf("prompt did not carry the figures: %q", *prompt)
	}

	refusing, _ := fakeModel(t, "", "refusal")
	if _, err := refusing.Summarise(context.Background(), []byte(`{}`)); !errors.Is(err, errSummaryFailed) {
		t.Errorf("refusal: err = %v, want errSummaryFailed", err)
	}
	empty, _ := fakeModel(t, "   ", "end_turn")
	if _, err := empty.Summarise(context.Background(), []byte(`{}`)); !errors.Is(err, errSummaryFailed) {
		t.Errorf("empty reply: err = %v, want errSummaryFailed", err)
	}
	long, _ := fakeModel(t, strings.Repeat("word ", 200), "end_turn")
	note, err = long.Summarise(context.Background(), []byte(`{}`))
	if err != nil || len([]rune(note)) > maxSummaryNote {
		t.Errorf("long reply: len %d err %v", len([]rune(note)), err)
	}
}
