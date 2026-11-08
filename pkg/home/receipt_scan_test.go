package home

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestReceiptFromReplyFillsAnEntry(t *testing.T) {
	now := time.Date(2026, 11, 8, 22, 0, 0, 0, time.UTC)
	cases := map[string]struct {
		reply string
		want  ReceiptScan
	}{
		"a UPI payment with paise": {
			`{"amount":173.5,"payee":"  Badam   Milk Stall ","direction":"paid","date":"2026-11-07"}`,
			ReceiptScan{AmountMinor: 17350, Payee: "Badam Milk Stall", Type: "expense", OccurredOn: "2026-11-07"},
		},
		"money received is income": {
			`{"amount":5000,"payee":"Nikita","direction":"received","date":"2026-11-08"}`,
			ReceiptScan{AmountMinor: 500000, Payee: "Nikita", Type: "income", OccurredOn: "2026-11-08"},
		},
		"no date in the picture keeps the day empty": {
			`{"amount":60,"payee":"Zepto","direction":"paid","date":""}`,
			ReceiptScan{AmountMinor: 6000, Payee: "Zepto", Type: "expense", OccurredOn: ""},
		},
		"a date in the future is dropped": {
			`{"amount":60,"payee":"Zepto","direction":"paid","date":"2027-01-01"}`,
			ReceiptScan{AmountMinor: 6000, Payee: "Zepto", Type: "expense", OccurredOn: ""},
		},
		"a date over a year old is dropped": {
			`{"amount":60,"payee":"Zepto","direction":"paid","date":"2025-10-01"}`,
			ReceiptScan{AmountMinor: 6000, Payee: "Zepto", Type: "expense", OccurredOn: ""},
		},
		"a malformed date is dropped": {
			`{"amount":60,"payee":"Zepto","direction":"paid","date":"07/11/2026"}`,
			ReceiptScan{AmountMinor: 6000, Payee: "Zepto", Type: "expense", OccurredOn: ""},
		},
		"tomorrow is allowed for a server behind IST": {
			`{"amount":60,"payee":"Zepto","direction":"paid","date":"2026-11-09"}`,
			ReceiptScan{AmountMinor: 6000, Payee: "Zepto", Type: "expense", OccurredOn: "2026-11-09"},
		},
		"the cap itself is allowed": {
			`{"amount":1000000000,"payee":"Builder","direction":"paid","date":""}`,
			ReceiptScan{AmountMinor: maxAmountMinor, Payee: "Builder", Type: "expense", OccurredOn: ""},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := receiptFromReply(tc.reply, now)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestReceiptFromReplyRefusesWhatIsNotAPayment(t *testing.T) {
	now := time.Date(2026, 11, 8, 22, 0, 0, 0, time.UTC)
	cases := map[string]string{
		"no payment in the picture": `{"amount":0,"payee":"","direction":"none","date":""}`,
		"zero amount":               `{"amount":0,"payee":"Zepto","direction":"paid","date":""}`,
		"negative amount":           `{"amount":-20,"payee":"Zepto","direction":"paid","date":""}`,
		"over the cap":              `{"amount":1000000000.01,"payee":"Zepto","direction":"paid","date":""}`,
		"no payee":                  `{"amount":60,"payee":"   ","direction":"paid","date":""}`,
		"payee too long":            `{"amount":60,"payee":"` + strings.Repeat("x", maxPayeeText+1) + `","direction":"paid","date":""}`,
		"unknown direction":         `{"amount":60,"payee":"Zepto","direction":"maybe","date":""}`,
		"not json":                  `Rs.60 paid to Zepto`,
	}
	for name, reply := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := receiptFromReply(reply, now); err == nil {
				t.Fatal("expected the reply to be refused")
			}
		})
	}
}

func TestReadReceiptAsksForOnePaymentAndMapsTheAnswer(t *testing.T) {
	vision, prompt := fakeModel(t, `{"amount":173,"payee":"Badam Milk Stall","direction":"paid","date":""}`, "end_turn")
	scan, err := vision.ReadReceipt(context.Background(), base64.StdEncoding.EncodeToString([]byte("png bytes")), "image/png")
	if err != nil {
		t.Fatal(err)
	}
	if scan.AmountMinor != 17300 || scan.Payee != "Badam Milk Stall" || scan.Type != "expense" || scan.OccurredOn != "" {
		t.Fatalf("scan: %+v", scan)
	}
	if !strings.Contains(*prompt, "never the account balance") || !strings.Contains(*prompt, "yyyy-mm-dd") {
		t.Fatalf("prompt did not pin the amount and date rules: %s", *prompt)
	}
	if fakeModelSeen != receiptModel || receiptModel != "claude-haiku-4-5-20251001" {
		t.Fatalf("receipts must be read by Haiku, got %q", fakeModelSeen)
	}
	for name, tc := range map[string]struct{ reply, stop string }{
		"no payment": {`{"amount":0,"payee":"","direction":"none","date":""}`, "end_turn"},
		"refusal":    {`{}`, "refusal"},
		"not json":   {`a receipt`, "end_turn"},
	} {
		t.Run(name, func(t *testing.T) {
			vision, _ := fakeModel(t, tc.reply, tc.stop)
			if _, err := vision.ReadReceipt(context.Background(), "aGk=", "image/jpeg"); err != errScanFailed {
				t.Fatalf("expected scan_failed, got %v", err)
			}
		})
	}
}

func TestScanReceiptRouteNeedsAKeyAndAToken(t *testing.T) {
	server, username, password := testServer(t)
	if status, _ := call(t, server, http.MethodPost, "/v1/entries/scan", "", map[string]any{"image": "aGk=", "mediaType": "image/jpeg"}); status != http.StatusUnauthorized {
		t.Fatalf("without a token: %d", status)
	}
	token := signIn(t, server, username, password)
	status, body := call(t, server, http.MethodPost, "/v1/entries/scan", token, map[string]any{"image": "aGk=", "mediaType": "image/jpeg"})
	if status != http.StatusServiceUnavailable || body["error"].(map[string]any)["code"] != "scan_unavailable" {
		t.Fatalf("without a key: %d %v", status, body)
	}
}
