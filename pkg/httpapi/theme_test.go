package httpapi

import (
	"net/http"
	"testing"
)

func TestCustomThemeIsStoredCleanedAndCleared(t *testing.T) {
	// Arrange
	h := newHarness(t)
	session := h.signUp("themer")
	theme := map[string]any{
		"base":  "graphite",
		"light": map[string]any{"accent": "#2E3192", "onAccent": "#FFFFFF"},
		"dark":  map[string]any{"accent": "#8B8FE8"},
	}

	// Act
	rec := h.do(http.MethodPatch, "/v1/me", session, map[string]any{"palette": "graphite", "customTheme": theme})

	// Assert
	requireStatus(t, rec, http.StatusOK)
	body := decodeBody(t, rec)
	if body["palette"] != "graphite" {
		t.Fatalf("palette not updated: %s", rec.Body.String())
	}
	stored, ok := body["customTheme"].(map[string]any)
	if !ok {
		t.Fatalf("customTheme not returned: %s", rec.Body.String())
	}
	if stored["base"] != "graphite" {
		t.Errorf("base = %v, want graphite", stored["base"])
	}
	if light, _ := stored["light"].(map[string]any); light["accent"] != "#2E3192" {
		t.Errorf("light accent = %v, want #2E3192", light["accent"])
	}

	reread := h.do(http.MethodGet, "/v1/me", session, nil)
	requireStatus(t, reread, http.StatusOK)
	if _, held := decodeBody(t, reread)["customTheme"].(map[string]any); !held {
		t.Errorf("custom theme did not survive a re-read: %s", reread.Body.String())
	}

	untouched := h.do(http.MethodPatch, "/v1/me", session, map[string]any{"theme": "dark"})
	requireStatus(t, untouched, http.StatusOK)
	if _, held := decodeBody(t, untouched)["customTheme"].(map[string]any); !held {
		t.Errorf("a patch that never mentions the theme must leave it alone: %s", untouched.Body.String())
	}

	cleared := h.do(http.MethodPatch, "/v1/me", session, map[string]any{"customTheme": nil})
	requireStatus(t, cleared, http.StatusOK)
	if decodeBody(t, cleared)["customTheme"] != nil {
		t.Errorf("customTheme should be null once cleared: %s", cleared.Body.String())
	}
}

func TestCustomThemeRejectsWhatItCannotStore(t *testing.T) {
	// Arrange
	h := newHarness(t)
	session := h.signUp("themer")

	cases := map[string]map[string]any{
		"unknown base":  {"base": "neon", "light": map[string]any{}},
		"unknown slot":  {"base": "cream", "light": map[string]any{"sidebar": "#FFFFFF"}},
		"not a colour":  {"base": "cream", "light": map[string]any{"accent": "javascript:alert(1)"}},
		"short hex":     {"base": "cream", "dark": map[string]any{"accent": "#FFF"}},
		"not an object": nil,
	}

	for name, theme := range cases {
		t.Run(name, func(t *testing.T) {
			// Act
			body := map[string]any{"customTheme": theme}
			if theme == nil {
				body["customTheme"] = "cream"
			}
			rec := h.do(http.MethodPatch, "/v1/me", session, body)

			// Assert
			requireStatus(t, rec, http.StatusBadRequest)
		})
	}
}
