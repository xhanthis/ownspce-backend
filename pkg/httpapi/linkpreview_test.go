package httpapi

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ownspce/backend/pkg/linkpreview"
)

func TestLinkPreviewNeedsASignedInUser(t *testing.T) {
	h := newHarness(t)
	rec := h.do(http.MethodPost, "/v1/link-preview", nil, map[string]string{"url": "https://example.com"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestLinkPreviewRefusesAddressesInsideTheNetwork(t *testing.T) {
	h := newHarness(t)
	alice := h.signUp("alice")

	cases := map[string]string{
		"http://169.254.169.254/latest/meta-data": "link_blocked",
		"http://localhost:8080/admin":             "link_blocked",
		"http://10.0.0.5/":                        "link_blocked",
		"javascript:alert(1)":                     "invalid_request",
		"":                                        "invalid_request",
	}
	for raw, wantCode := range cases {
		rec := h.do(http.MethodPost, "/v1/link-preview", alice, map[string]string{"url": raw})
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%q: status = %d, want 400", raw, rec.Code)
			continue
		}
		body := decodeBody(t, rec)
		if got := body["error"].(map[string]any)["code"]; got != wantCode {
			t.Errorf("%q: code = %v, want %s", raw, got, wantCode)
		}
	}
}

func TestLinkPreviewReturnsWhatThePageSaysAboutItself(t *testing.T) {
	h := newHarness(t)
	alice := h.signUp("alice")
	// The production fetcher refuses loopback, which is where httptest lives;
	// the handler's own logic is what is under test here.
	h.server.previews = linkpreview.NewUnsafeForTests()

	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>An article</title><meta property="og:description" content="Worth reading"><meta property="og:image" content="/cover.png"></head><body></body></html>`)
	}))
	defer site.Close()

	rec := h.do(http.MethodPost, "/v1/link-preview", alice, map[string]string{"url": site.URL + "/post"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	if body["title"] != "An article" || body["description"] != "Worth reading" || body["image"] != site.URL+"/cover.png" {
		t.Errorf("preview = %v", body)
	}
	if body["url"] != site.URL+"/post" || body["icon"] != site.URL+"/favicon.ico" {
		t.Errorf("url/icon = %v/%v", body["url"], body["icon"])
	}
}

func TestLinkPreviewReportsAPageItCannotRead(t *testing.T) {
	h := newHarness(t)
	alice := h.signUp("alice")
	h.server.previews = linkpreview.NewUnsafeForTests()

	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pdf")
		fmt.Fprint(w, "%PDF-1.7")
	}))
	defer site.Close()

	rec := h.do(http.MethodPost, "/v1/link-preview", alice, map[string]string{"url": site.URL + "/paper.pdf"})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", rec.Code)
	}
	if got := decodeBody(t, rec)["error"].(map[string]any)["code"]; got != "preview_unavailable" {
		t.Errorf("code = %v", got)
	}
}

func TestLinkPreviewIsRateLimitedPerUser(t *testing.T) {
	h := newHarness(t)
	alice := h.signUp("alice")
	bob := h.signUp("bob")

	// Every call is refused before any page is fetched, so the limiter is the
	// only thing being counted here.
	for i := 0; i < 60; i++ {
		rec := h.do(http.MethodPost, "/v1/link-preview", alice, map[string]string{"url": "http://10.0.0.5/"})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("call %d: status = %d, want 400 before the limit", i+1, rec.Code)
		}
	}
	rec := h.do(http.MethodPost, "/v1/link-preview", alice, map[string]string{"url": "http://10.0.0.5/"})
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("61st call: status = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("429 should say when to come back")
	}
	if got := h.do(http.MethodPost, "/v1/link-preview", bob, map[string]string{"url": "http://10.0.0.5/"}).Code; got != http.StatusBadRequest {
		t.Errorf("another user is limited separately: status = %d, want 400", got)
	}
}
