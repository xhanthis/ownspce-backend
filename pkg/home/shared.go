package home

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"sync"
)

var (
	sharedMu      sync.Mutex
	sharedHandler http.Handler
)

// Shared returns the process-wide Home handler for a serverless entrypoint, opening the
// database named by HOME_DATABASE_URL on first use.
// Returns: the handler, or an error when HOME_DATABASE_URL is unset or the database is unreachable
// Handles: a failed open is not cached, so the next request on a warm instance retries; a failed dish seed is
// logged and the API still serves, since the library is a convenience and not a dependency
func Shared(ctx context.Context) (http.Handler, error) {
	sharedMu.Lock()
	defer sharedMu.Unlock()
	if sharedHandler != nil {
		return sharedHandler, nil
	}
	databaseURL := os.Getenv("HOME_DATABASE_URL")
	if databaseURL == "" {
		return nil, errors.New("HOME_DATABASE_URL is not set")
	}
	store, err := Open(ctx, databaseURL)
	if err != nil {
		return nil, err
	}
	if added, err := store.SeedDishes(ctx); err != nil {
		log.Printf("seed dishes: %v", err)
	} else if added > 0 {
		log.Printf("seeded %d default dishes", added)
	}
	sharedHandler = NewServer(store, ConfigFromEnv())
	return sharedHandler, nil
}
