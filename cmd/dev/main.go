// Command dev runs the same chi router as the Vercel function over a local HTTP
// listener, so the API can be exercised end to end without vercel dev.
// Usage: go run ./cmd/dev  (reads .env if present, PORT defaults to 8080)
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/ownspce/backend/pkg/dotenv"
	"github.com/ownspce/backend/pkg/httpapi"
)

func main() {
	dotenv.Load(".env")

	server, err := httpapi.Shared(context.Background())
	if err != nil {
		log.Fatalf("startup failed: %v", err)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	srv := &http.Server{Addr: ":" + port, Handler: server, ReadHeaderTimeout: 5 * time.Second}
	log.Printf("ownspce api listening on http://localhost:%s/v1", port)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server stopped: %v", err)
	}
}
