// Package mailer sends the few transactional emails the API has to send. It is
// one HTTP call to AutoSend and no dependency, because a mail library that can
// do everything is a lot of surface for a product that sends one kind of
// message.
package mailer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

const autosendEndpoint = "https://api.autosend.com/v1/mails/send"

// ErrNotConfigured means there is no way to send mail. In production that is a
// failure the caller must surface; in development it never happens, because the
// code is logged instead.
var ErrNotConfigured = errors.New("mailer: no email provider configured")

type Mailer struct {
	apiKey     string
	from       address
	production bool
	client     *http.Client
}

// New builds a mailer. An empty apiKey outside production is deliberate and
// supported: the code is written to the log so local sign-in works without an
// account at a mail provider. In production the same emptiness is an error at
// send time rather than a silently dropped email.
func New(apiKey, fromAddress, fromName string, production bool) *Mailer {
	return &Mailer{apiKey: apiKey, from: address{Email: fromAddress, Name: fromName}, production: production, client: &http.Client{Timeout: 10 * time.Second}}
}

// Configured reports whether mail can actually leave this process.
func (m *Mailer) Configured() bool { return m.apiKey != "" || !m.production }

// SendSignInCode mails the code that creates or resumes an account.
func (m *Mailer) SendSignInCode(ctx context.Context, to, code string, ttl time.Duration) error {
	minutes := int(ttl.Minutes())
	return m.send(ctx, to, "Your OwnSpce sign-in code",
		fmt.Sprintf("Your OwnSpce sign-in code is %s.\n\nIt works for the next %d minutes and once only. If you did not ask to sign in, ignore this — nobody can use the code without this email.\n", code, minutes),
		codeHTML("Sign in to OwnSpce", code, fmt.Sprintf("This code works for the next %d minutes, once. If you did not ask to sign in, you can ignore this email.", minutes)))
}

// SendDeviceCode mails the code that lets a new device into an existing account.
// The wording carries the limit deliberately: this code admits a device, and a
// device that is admitted still holds no household key.
func (m *Mailer) SendDeviceCode(ctx context.Context, to, code, deviceLabel string, ttl time.Duration) error {
	minutes := int(ttl.Minutes())
	if deviceLabel == "" {
		deviceLabel = "a new device"
	}
	return m.send(ctx, to, "Code to let a new device into OwnSpce",
		fmt.Sprintf("Your code to let %s into your OwnSpce account is %s.\n\nIt works for the next %d minutes and once only. If this was not you, do not enter it — someone with this code could sign in on their own device. They still could not read anything you have encrypted.\n", deviceLabel, code, minutes),
		codeHTML("Let a new device in", code, fmt.Sprintf("This admits %s to your account for the next %d minutes. If it was not you, ignore this email and change nothing.", deviceLabel, minutes)))
}

// address is AutoSend's sender/recipient shape: an object, not a header string.
type address struct {
	Email string `json:"email"`
	Name  string `json:"name,omitempty"`
}

type autosendRequest struct {
	From    address `json:"from"`
	To      address `json:"to"`
	Subject string  `json:"subject"`
	Text    string  `json:"text"`
	HTML    string  `json:"html"`
}

// send posts one email, or logs it when there is no provider outside production.
// Args: ctx, to, subject, text and html bodies
// Returns: nil on a 2xx, ErrNotConfigured with no key in production, or an error
// carrying the provider's status — never the body, which can echo the address
// Handles: a provider outage, which fails the request rather than pretending the
// mail was sent; a caller must not be told to check an inbox that will stay empty
func (m *Mailer) send(ctx context.Context, to, subject, text, html string) error {
	if m.apiKey == "" {
		if m.production {
			return ErrNotConfigured
		}
		log.Printf("[mailer] no AUTOSEND_API_KEY; would have sent to %s: %s", to, text)
		return nil
	}

	payload, err := json.Marshal(autosendRequest{From: m.from, To: address{Email: to}, Subject: subject, Text: text, HTML: html})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, autosendEndpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+m.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return fmt.Errorf("send email: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("send email: provider returned %d", resp.StatusCode)
	}
	return nil
}

// codeHTML renders the one email layout this package has. Inline styles only:
// every mail client strips a stylesheet, and a code nobody can read is a support
// ticket.
func codeHTML(heading, code, footnote string) string {
	return fmt.Sprintf(`<!doctype html><html><body style="margin:0;padding:32px 16px;background:#F4EFE7;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;color:#2B2621">`+
		`<div style="max-width:420px;margin:0 auto;background:#FFFCF7;border:1px solid #E3D9CB;border-radius:16px;padding:28px">`+
		`<div style="font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:#B0745A;font-weight:700">OwnSpce</div>`+
		`<h1 style="font-size:20px;margin:12px 0 18px;font-weight:800">%s</h1>`+
		`<div style="font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:32px;font-weight:700;letter-spacing:.22em;background:#F4EFE7;border-radius:12px;padding:16px;text-align:center">%s</div>`+
		`<p style="font-size:13px;line-height:1.6;color:#6B6157;margin:18px 0 0">%s</p>`+
		`</div></body></html>`, heading, code, footnote)
}
