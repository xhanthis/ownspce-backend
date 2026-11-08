package home

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/go-chi/chi/v5/middleware"
)

const dishScanPath = "/v1/dishes/scan"

const dishScanPrompt = `This is a photo of a dish from a pure-vegetarian Indian home kitchen in Pune. Name the dish in one to four words the way the family would say it ("Misal Pav", "Dal Rice", "Masala Chai"); when the plate holds several things, name the plate ("Thali", "Chapati Sabzi"). Give calories, protein, carbs and fat for the ONE serving in the photo as one adult would eat it (count every chapati, the rice, the sides). Then list the ingredients needed to cook the dish for TWO people, each with a short plain name (no brand) and an amount the kitchen can count: grams or kilograms for solids ("200 g", "1 kg"), millilitres or litres for liquids ("250 ml"), pieces for countable things ("2 pcs"). Skip spices, salt, oil and other pantry staples. At most 12 ingredients. If the photo shows no food, answer with an empty name, zero calories and no ingredients.`

var dishScanSchema = dishSchemaWith("name")

// DishScan is what the Add dish sheet fills from a photo: the dish the reader saw plus the same per-plate numbers
// and recipe an estimate has.
type DishScan struct {
	Name string `json:"name"`
	DishEstimate
}

// ReadDish names the dish in one photo and estimates it, through the same checks a posted meal gets.
// Args: ctx, image (base64, already size-checked by the caller), mediaType (image/jpeg and friends)
// Returns: the scan with serves 2; errScanFailed when the model errors, refuses, sees no food, or answers out of range
func (v *Vision) ReadDish(ctx context.Context, image, mediaType string) (DishScan, error) {
	started := time.Now()
	response, err := v.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:        visionModel,
		MaxTokens:    1200,
		OutputConfig: anthropic.OutputConfigParam{Effort: anthropic.OutputConfigEffortLow, Format: anthropic.JSONOutputFormatParam{Schema: dishScanSchema}},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewImageBlockBase64(mediaType, image), anthropic.NewTextBlock(dishScanPrompt)),
		},
	})
	if err != nil {
		log.Printf("dish scan: model call failed after %s: %v", time.Since(started).Round(time.Millisecond), err)
		return DishScan{}, errScanFailed
	}
	if response.StopReason == anthropic.StopReasonRefusal {
		log.Printf("dish scan: model declined the photo")
		return DishScan{}, errScanFailed
	}
	estimate, name, err := dishFromReply(replyText(response), "")
	if err != nil {
		log.Printf("dish scan: %v", err)
		return DishScan{}, errScanFailed
	}
	if estimate.Kcal == 0 {
		log.Printf("dish scan: no food in the photo")
		return DishScan{}, errScanFailed
	}
	log.Printf("dish scan: ok in %s, %d ingredients, %d in / %d out tokens", time.Since(started).Round(time.Millisecond), len(estimate.Ingredients), response.Usage.InputTokens, response.Usage.OutputTokens)
	return DishScan{Name: name, DishEstimate: estimate}, nil
}

// scanDish fills the Add dish sheet from a photo: POST /v1/dishes/scan {image, mediaType}. Nothing is written: the
// member checks the name and numbers, then saves through addMeal.
// Handles: no key on the server (503), a non-image or oversized upload (400), a photo without a dish (502)
func (s *Server) scanDish(w http.ResponseWriter, r *http.Request) {
	if s.vision == nil {
		writeError(w, r, errScanUnavailable)
		return
	}
	body, err := readScanBody(r)
	if err != nil {
		writeError(w, r, err)
		return
	}
	scan, err := s.vision.ReadDish(r.Context(), body.Image, body.MediaType)
	if err != nil {
		log.Printf("[%s] dish scan failed", middleware.GetReqID(r.Context()))
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, scan)
}
