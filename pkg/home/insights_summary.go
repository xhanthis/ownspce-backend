package home

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/go-chi/chi/v5/middleware"
)

const (
	insightsSummaryPath = "/v1/insights/summary"
	summaryModel        = receiptModel
	maxSummaryFigures   = 60
	maxSummaryKey       = 40
	maxSummaryValue     = 80
	maxSummaryNote      = 400
	maxSummaryCallsADay = 12
	summaryMaxTokens    = 200
)

var errSummaryUnavailable = apiError{status: http.StatusServiceUnavailable, Code: "summary_unavailable", Message: "insight notes are not set up on this server"}
var errSummaryFailed = apiError{status: http.StatusBadGateway, Code: "summary_failed", Message: "could not write the note this time"}

const summaryPrompt = `You coach one person on their household money, body and meals. Below are their figures for a chosen date range, as JSON. Keys ending in "Prev" are the same figure for the range just before. Money is in Indian rupees, weights in kilograms, food in kilocalories and grams.
Write exactly two short sentences in plain English, addressed as "you": first, the one thing that moved most or matters most (good or bad); second, the single most useful thing to do next. Use at most two numbers in total. No greeting, no headings, no bullet points, no markdown, no emoji.

%s`

// validateFigures accepts a flat object of short keys to numbers, booleans or short strings, and returns it
// encoded with sorted keys so the same figures always hash the same.
// Handles: nested objects or arrays (refused), too many keys, long keys or strings
func validateFigures(figures map[string]any) ([]byte, error) {
	if len(figures) == 0 || len(figures) > maxSummaryFigures {
		return nil, badRequest(fmt.Sprintf("figures must hold 1 to %d values", maxSummaryFigures))
	}
	for key, value := range figures {
		if !textBetween(key, 1, maxSummaryKey) {
			return nil, badRequest(fmt.Sprintf("figure names must be 1 to %d characters", maxSummaryKey))
		}
		switch typed := value.(type) {
		case float64, bool, nil:
		case string:
			if utf8.RuneCountInString(typed) > maxSummaryValue {
				return nil, badRequest(fmt.Sprintf("figure %q is longer than %d characters", key, maxSummaryValue))
			}
		default:
			return nil, badRequest(fmt.Sprintf("figure %q must be a number, text or true/false", key))
		}
	}
	encoded, err := json.Marshal(figures)
	if err != nil {
		return nil, fmt.Errorf("encode figures: %w", err)
	}
	return encoded, nil
}

func figuresHash(encoded []byte) string {
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

// Summarise asks the small model for a two-sentence note on one set of figures.
// Returns: the trimmed note; errSummaryFailed when the model errors, refuses or answers nothing usable
func (v *Vision) Summarise(ctx context.Context, figures []byte) (string, error) {
	started := time.Now()
	response, err := v.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     summaryModel,
		MaxTokens: summaryMaxTokens,
		Messages:  []anthropic.MessageParam{anthropic.NewUserMessage(anthropic.NewTextBlock(fmt.Sprintf(summaryPrompt, figures)))},
	})
	if err != nil {
		log.Printf("insight note: model call failed after %s: %v", time.Since(started).Round(time.Millisecond), err)
		return "", errSummaryFailed
	}
	if response.StopReason == anthropic.StopReasonRefusal {
		log.Printf("insight note: model declined")
		return "", errSummaryFailed
	}
	note := strings.Join(strings.Fields(replyText(response)), " ")
	if note == "" {
		return "", errSummaryFailed
	}
	if utf8.RuneCountInString(note) > maxSummaryNote {
		runes := []rune(note)
		note = strings.TrimSpace(string(runes[:maxSummaryNote]))
	}
	return note, nil
}

type summaryBody struct {
	Figures map[string]any `json:"figures"`
}

// insightsSummary answers the Insights page's note: POST /v1/insights/summary {figures} → {note}. The same figures
// are written once and then served from the store; a member gets at most twelve fresh notes a day, after which the
// newest note they have comes back instead of a model call.
// Handles: no key on the server (503), bad figures (400), a model failure (502)
func (s *Server) insightsSummary(w http.ResponseWriter, r *http.Request) {
	if s.vision == nil {
		writeError(w, r, errSummaryUnavailable)
		return
	}
	var body summaryBody
	if err := decode(r, &body); err != nil {
		writeError(w, r, err)
		return
	}
	encoded, err := validateFigures(body.Figures)
	if err != nil {
		writeError(w, r, err)
		return
	}
	user := actor(r).ID
	hash := figuresHash(encoded)
	if note, err := s.store.InsightNote(r.Context(), user, hash); err == nil {
		writeJSON(w, http.StatusOK, map[string]any{"note": note, "fresh": false})
		return
	} else if !errors.Is(err, ErrNotFound) {
		writeError(w, r, err)
		return
	}
	calls, err := s.store.InsightNotesToday(r.Context(), user)
	if err != nil {
		writeError(w, r, err)
		return
	}
	if calls >= maxSummaryCallsADay {
		note, err := s.store.LatestInsightNote(r.Context(), user)
		if err != nil && !errors.Is(err, ErrNotFound) {
			writeError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"note": note, "fresh": false})
		return
	}
	note, err := s.vision.Summarise(r.Context(), encoded)
	if err != nil {
		log.Printf("[%s] insight note failed", middleware.GetReqID(r.Context()))
		writeError(w, r, err)
		return
	}
	if err := s.store.SaveInsightNote(r.Context(), user, hash, note); err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"note": note, "fresh": true})
}
