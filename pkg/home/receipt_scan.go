package home

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/go-chi/chi/v5/middleware"
)

const receiptScanPath = "/v1/entries/scan"

const receiptScanPrompt = `This is a screenshot or photo of one payment record from India: a UPI app receipt (Google Pay, PhonePe, Paytm, BHIM, a bank app), a bank SMS or notification, a card slip, or a shop bill. Read the ONE payment it shows. amount: the rupees of that payment as a number, with paise after the point when shown (173 or 173.50); never the account balance, a cashback, a reward, a limit or a total of several payments. payee: who was paid or who paid, in two to five plain words the way a person writes it in a ledger ("Badam Milk Stall", "Zepto", "Mahesh Barber"); drop UPI handles, bank codes, reference numbers, phone numbers and words like "Paid to". direction: "paid" when money left this person's account, "received" when it came in, "none" when the picture shows no payment. date: the day of the payment as yyyy-mm-dd when the picture shows one, else "". If the picture shows no payment, answer with amount 0, an empty payee and direction "none".`

var receiptScanSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"amount":    map[string]any{"type": "number"},
		"payee":     map[string]any{"type": "string"},
		"direction": map[string]any{"type": "string", "enum": []string{"paid", "received", "none"}},
		"date":      map[string]any{"type": "string"},
	},
	"required":             []string{"amount", "payee", "direction", "date"},
	"additionalProperties": false,
}

// receiptModel reads receipts: a screenshot of printed numbers needs far less than a plate of food, and Haiku answers
// in about a second.
const receiptModel = "claude-haiku-4-5-20251001"

const maxPayeeText = 80

var receiptDirections = map[string]string{"paid": "expense", "received": "income"}

// ReceiptScan is what the Money log sheet fills from a payment screenshot: the amount in paise, who was paid as the
// note, expense or income, and the day when the picture showed one (empty otherwise, the sheet keeps today).
type ReceiptScan struct {
	AmountMinor int64  `json:"amountMinor"`
	Payee       string `json:"payee"`
	Type        string `json:"type"`
	OccurredOn  string `json:"occurredOn"`
}

// ReadReceipt reads one payment screenshot into the fields of an entry, through the same limits a posted entry gets.
// Args: ctx, image (base64, already size-checked by the caller), mediaType (image/jpeg and friends)
// Returns: the scan; errScanFailed when the model errors, refuses, sees no payment, or answers out of range
func (v *Vision) ReadReceipt(ctx context.Context, image, mediaType string) (ReceiptScan, error) {
	started := time.Now()
	response, err := v.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:        receiptModel,
		MaxTokens:    300,
		OutputConfig: anthropic.OutputConfigParam{Format: anthropic.JSONOutputFormatParam{Schema: receiptScanSchema}},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewImageBlockBase64(mediaType, image), anthropic.NewTextBlock(receiptScanPrompt)),
		},
	})
	if err != nil {
		log.Printf("receipt scan: model call failed after %s: %v", time.Since(started).Round(time.Millisecond), err)
		return ReceiptScan{}, errScanFailed
	}
	if response.StopReason == anthropic.StopReasonRefusal {
		log.Printf("receipt scan: model declined the picture")
		return ReceiptScan{}, errScanFailed
	}
	scan, err := receiptFromReply(replyText(response), time.Now())
	if err != nil {
		log.Printf("receipt scan: %v", err)
		return ReceiptScan{}, errScanFailed
	}
	log.Printf("receipt scan: ok in %s, %d in / %d out tokens", time.Since(started).Round(time.Millisecond), response.Usage.InputTokens, response.Usage.OutputTokens)
	return scan, nil
}

// receiptFromReply turns the model's JSON into a scan the entry route would accept: paise from a rupee number, a
// tidy payee, expense or income from the direction, and a day only when it is a real date that is not in the future
// and not over a year old (a misread date must not file a spend in the wrong month).
// Returns: the scan, or why the reply is unusable
func receiptFromReply(text string, now time.Time) (ReceiptScan, error) {
	var parsed struct {
		Amount    float64
		Payee     string
		Direction string
		Date      string
	}
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		return ReceiptScan{}, fmt.Errorf("reply was not the expected shape: %w", err)
	}
	kind, known := receiptDirections[parsed.Direction]
	if !known {
		return ReceiptScan{}, errors.New("no payment in the picture")
	}
	if math.IsNaN(parsed.Amount) || math.IsInf(parsed.Amount, 0) || parsed.Amount <= 0 || parsed.Amount*100 > float64(maxAmountMinor) {
		return ReceiptScan{}, fmt.Errorf("amount %v is out of range", parsed.Amount)
	}
	payee := strings.Join(strings.Fields(parsed.Payee), " ")
	if !textBetween(payee, 1, maxPayeeText) {
		return ReceiptScan{}, errors.New("reply named no payee")
	}
	day := parsed.Date
	oldest := now.AddDate(-1, 0, 0).Format("2006-01-02")
	latest := now.AddDate(0, 0, 1).Format("2006-01-02")
	if !validDate(day) || day < oldest || day > latest {
		day = ""
	}
	return ReceiptScan{AmountMinor: int64(math.Round(parsed.Amount * 100)), Payee: payee, Type: kind, OccurredOn: day}, nil
}

// scanReceipt fills the Money log sheet from a payment screenshot: POST /v1/entries/scan {image, mediaType}. Nothing
// is written: the member checks the fields, then saves through createEntry.
// Handles: no key on the server (503), a non-image or oversized upload (400), a picture without a payment (502)
func (s *Server) scanReceipt(w http.ResponseWriter, r *http.Request) {
	if s.vision == nil {
		writeError(w, r, errScanUnavailable)
		return
	}
	body, err := readScanBody(r)
	if err != nil {
		writeError(w, r, err)
		return
	}
	scan, err := s.vision.ReadReceipt(r.Context(), body.Image, body.MediaType)
	if err != nil {
		log.Printf("[%s] receipt scan failed", middleware.GetReqID(r.Context()))
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, scan)
}
