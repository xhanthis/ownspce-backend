package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ownspce/backend/pkg/config"
)

// clientRequestHeaders is every header the sync client attaches to an authed
// request. Any one of them missing from the preflight allowlist makes the
// browser reject the request with HeaderDisallowedByPreflightResponse before it
// is ever sent, which reads as a CORS error on /me, /devices and /spaces while
// the unauthenticated routes keep working.
var clientRequestHeaders = []string{"Authorization", "Content-Type", "If-None-Match", "X-Device-ID"}

// TestPreflightAllowsEveryClientHeader asserts the CORS allowlist covers each
// header the client sends on an authenticated request.
// Handles: browsers lowercasing header names in Access-Control-Request-Headers.
func TestPreflightAllowsEveryClientHeader(t *testing.T) {
	server := &Server{cfg: &config.Config{Env: "development"}}
	handler := server.cors(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	request := httptest.NewRequest(http.MethodOptions, "/v1/spaces", nil)
	request.Header.Set("Origin", "http://localhost:5173")
	request.Header.Set("Access-Control-Request-Method", http.MethodGet)
	request.Header.Set("Access-Control-Request-Headers", strings.ToLower(strings.Join(clientRequestHeaders, ",")))
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("preflight status = %d, want %d", recorder.Code, http.StatusNoContent)
	}
	allowed := strings.ToLower(recorder.Header().Get("Access-Control-Allow-Headers"))
	for _, header := range clientRequestHeaders {
		if !strings.Contains(allowed, strings.ToLower(header)) {
			t.Errorf("Access-Control-Allow-Headers %q is missing %q", allowed, header)
		}
	}
}

// TestPreflightRejectsUnknownOriginInProduction asserts the localhost escape
// hatch is development-only, so a hostile origin gets no CORS headers in
// production and the browser refuses to hand it a response.
func TestPreflightRejectsUnknownOriginInProduction(t *testing.T) {
	server := &Server{cfg: &config.Config{Env: "production", AllowedOrigins: []string{"https://app.ownspce.com"}}}
	handler := server.cors(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	for _, origin := range []string{"http://localhost:5173", "https://evil.example.com"} {
		request := httptest.NewRequest(http.MethodOptions, "/v1/spaces", nil)
		request.Header.Set("Origin", origin)
		recorder := httptest.NewRecorder()

		handler.ServeHTTP(recorder, request)

		if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("origin %q allowed in production, got Access-Control-Allow-Origin %q", origin, got)
		}
	}
}
