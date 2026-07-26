// Package handler is the single Vercel serverless entrypoint — the runtime
// requires this package name and generates the main shim around Handler.
// vercel.json rewrites every path here and chi does the routing inside, so warm
// invocations share one connection pool and one JWKS cache instead of one per
// route file.
package handler

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/ownspce/backend/pkg/httpapi"
)

// Handler is the function Vercel invokes for every request to api.ownspce.com.
func Handler(w http.ResponseWriter, r *http.Request) {
	server, err := httpapi.Shared(r.Context())
	if err != nil {
		log.Printf("startup failed: %v", err)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": "unavailable", "message": "the API is misconfigured or the database is unreachable"}})
		return
	}
	server.ServeHTTP(w, r)
}
