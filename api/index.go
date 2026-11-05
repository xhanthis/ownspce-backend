// Package handler is the single Vercel serverless entrypoint — the runtime
// requires this package name and generates the main shim around Handler.
// vercel.json rewrites every path here and chi does the routing inside, so warm
// invocations share one connection pool and one JWKS cache instead of one per
// route file. Paths under /home go to the separate, plain Home API.
package handler

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/ownspce/backend/pkg/home"
	"github.com/ownspce/backend/pkg/httpapi"
)

// homePrefix is where the plain Home API is mounted beside the OwnSpce API.
const homePrefix = "/home"

// Handler is the function Vercel invokes for every request to api.ownspce.com.
func Handler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == homePrefix || strings.HasPrefix(r.URL.Path, homePrefix+"/") {
		server, err := home.Shared(r.Context())
		if err != nil {
			log.Printf("home startup failed: %v", err)
			unavailable(w, "the Home API is not configured or its database is unreachable")
			return
		}
		http.StripPrefix(homePrefix, server).ServeHTTP(w, r)
		return
	}

	server, err := httpapi.Shared(r.Context())
	if err != nil {
		log.Printf("startup failed: %v", err)
		unavailable(w, "the API is misconfigured or the database is unreachable")
		return
	}
	server.ServeHTTP(w, r)
}

func unavailable(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusServiceUnavailable)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": "unavailable", "message": message}})
}
