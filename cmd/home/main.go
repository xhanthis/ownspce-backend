// Command home runs the Home API, or manages its accounts.
//
// Usage:
//
//	go run ./cmd/home                              serve on PORT (default 5002)
//	go run ./cmd/home adduser <username> "<Name>"  add an account; password read from stdin
//	go run ./cmd/home passwd <username>            replace a password; signs that account out everywhere
//
// HOME_DATABASE_URL must point at a Postgres database; the schema is applied on start.
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ownspce/backend/pkg/dotenv"
	"github.com/ownspce/backend/pkg/home"
)

func main() {
	dotenv.Load(".env")

	databaseURL := os.Getenv("HOME_DATABASE_URL")
	if databaseURL == "" {
		log.Fatal("HOME_DATABASE_URL is not set")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	store, err := home.Open(ctx, databaseURL)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer store.Close()

	args := os.Args[1:]
	switch {
	case len(args) == 0:
		serve(ctx, store)
	case args[0] == "adduser" && len(args) == 3:
		exitOn(addUser(ctx, store, args[1], args[2]))
	case args[0] == "passwd" && len(args) == 2:
		exitOn(changePassword(ctx, store, args[1]))
	default:
		fmt.Fprintln(os.Stderr, "usage: home | home adduser <username> \"<Name>\" | home passwd <username>")
		os.Exit(2)
	}
}

func serve(ctx context.Context, store *home.Store) {
	port := os.Getenv("PORT")
	if port == "" {
		port = "5002"
	}
	server := &http.Server{Addr: ":" + port, Handler: home.NewServer(store), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second}

	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()

	log.Printf("home api listening on http://localhost:%s/v1", port)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server stopped: %v", err)
	}
}

// addUser creates an account from a username, a display name and a password typed on stdin.
func addUser(ctx context.Context, store *home.Store, rawUsername, rawName string) error {
	username, ok := home.NormaliseUsername(rawUsername)
	if !ok {
		return errors.New("username must be 2-32 characters of a-z, 0-9, dot, underscore or dash")
	}
	name := strings.TrimSpace(rawName)
	if name == "" || len([]rune(name)) > 60 {
		return errors.New("name must be 1 to 60 characters")
	}
	hash, err := readPasswordHash()
	if err != nil {
		return err
	}
	if _, err := store.CreateUser(ctx, username, name, hash); err != nil {
		if errors.Is(err, home.ErrConflict) {
			return errors.New("that username is taken")
		}
		return err
	}
	fmt.Printf("added %s\n", username)
	return nil
}

// changePassword replaces an account's password with one typed on stdin.
func changePassword(ctx context.Context, store *home.Store, rawUsername string) error {
	username, ok := home.NormaliseUsername(rawUsername)
	if !ok {
		return errors.New("not a valid username")
	}
	hash, err := readPasswordHash()
	if err != nil {
		return err
	}
	if err := store.SetPassword(ctx, username, hash); err != nil {
		if errors.Is(err, home.ErrNotFound) {
			return errors.New("no such account")
		}
		return err
	}
	fmt.Printf("password changed for %s; every session on it is signed out\n", username)
	return nil
}

func readPasswordHash() (string, error) {
	fmt.Fprint(os.Stderr, "password: ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", errors.New("no password given")
	}
	return home.HashPassword(strings.TrimRight(line, "\r\n"))
}

func exitOn(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
