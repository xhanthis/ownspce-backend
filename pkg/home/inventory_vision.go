package home

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

const visionModel = "claude-sonnet-5"

// ScannedItem is one row the photo reader suggests. Qty is the same free text ParseQuantity reads.
type ScannedItem struct {
	Name string `json:"name"`
	Qty  string `json:"qty"`
}

// Vision turns a grocery photo into stock rows through Claude. Nil when the server has no key.
type Vision struct {
	client anthropic.Client
}

var errScanFailed = apiError{status: http.StatusBadGateway, Code: "scan_failed", Message: "could not read that photo, try a clearer one"}

const groceryPrompt = `List every food or kitchen item visible in this photo, one row each. For each give a short plain name (the thing, not the brand) and the amount as a short quantity: grams or kilograms for solids ("500 g", "1 kg"), millilitres or litres for liquids ("500 ml", "1 L"), and pieces for countable things ("6 pcs"). Read the net weight off a packet when it is printed; otherwise give your best estimate. Combine identical items into one row. Skip anything that is not food or kitchen stock. At most 40 rows; an empty list when there is nothing to list.`

var scanSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"items": map[string]any{
			"type": "array",
			"items": map[string]any{
				"type":                 "object",
				"properties":           map[string]any{"name": map[string]any{"type": "string"}, "qty": map[string]any{"type": "string"}},
				"required":             []string{"name", "qty"},
				"additionalProperties": false,
			},
		},
	},
	"required":             []string{"items"},
	"additionalProperties": false,
}

// NewVision builds the photo reader, or returns nil when there is no key so the scan route answers 503.
// The call gets one try inside the route's own timeout; a retry would overrun it.
func NewVision(apiKey string) *Vision {
	if apiKey == "" {
		return nil
	}
	return &Vision{client: anthropic.NewClient(option.WithAPIKey(apiKey), option.WithRequestTimeout(scanTimeout-5*time.Second), option.WithMaxRetries(0))}
}

// ReadGroceries asks the model for the items in one photo and keeps only rows whose amount the parser can read.
// Args: ctx, image (base64, already size-checked by the caller), mediaType (image/jpeg and friends)
// Returns: up to maxScanItems rows; errScanFailed when the model errors, refuses, or answers something unreadable
func (v *Vision) ReadGroceries(ctx context.Context, image, mediaType string) ([]ScannedItem, error) {
	response, err := v.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:        visionModel,
		MaxTokens:    2000,
		OutputConfig: anthropic.OutputConfigParam{Effort: anthropic.OutputConfigEffortLow, Format: anthropic.JSONOutputFormatParam{Schema: scanSchema}},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewImageBlockBase64(mediaType, image), anthropic.NewTextBlock(groceryPrompt)),
		},
	})
	if err != nil {
		log.Printf("inventory scan: model call failed: %v", err)
		return nil, errScanFailed
	}
	if response.StopReason == anthropic.StopReasonRefusal {
		log.Printf("inventory scan: model declined the photo")
		return nil, errScanFailed
	}
	var text strings.Builder
	for _, block := range response.Content {
		if textBlock, ok := block.AsAny().(anthropic.TextBlock); ok {
			text.WriteString(textBlock.Text)
		}
	}
	var parsed struct {
		Items []ScannedItem `json:"items"`
	}
	if err := json.Unmarshal([]byte(text.String()), &parsed); err != nil {
		log.Printf("inventory scan: reply was not the expected shape: %v", err)
		return nil, errScanFailed
	}
	items := make([]ScannedItem, 0, len(parsed.Items))
	for _, item := range parsed.Items {
		name, qty := displayName(item.Name), strings.TrimSpace(item.Qty)
		if _, ok := ParseQuantity(qty); !ok || !textBetween(name, 1, maxItemName) || !textBetween(qty, 1, maxQuantityText) {
			continue
		}
		items = append(items, ScannedItem{Name: name, Qty: qty})
		if len(items) == maxScanItems {
			break
		}
	}
	return items, nil
}
