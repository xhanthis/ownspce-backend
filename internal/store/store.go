// Package store owns every database access path. All SQL lives here so the
// HTTP layer never builds queries, and so the "server never reads content"
// rule is auditable in one place: ciphertext columns are only ever written and
// read back verbatim, never parsed or filtered on.
package store

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrNotFound  = errors.New("store: not found")
	ErrConflict  = errors.New("store: conflict")
	ErrForbidden = errors.New("store: forbidden")
)

type Store struct {
	pool *pgxpool.Pool
}

var (
	sharedOnce sync.Once
	shared     *Store
	sharedErr  error
)

// Shared returns the process-wide Store, opening the pool on first use.
// Serverless instances handle few concurrent requests each but are numerous, so
// the pool stays tiny and leans on Neon's PgBouncer for real fan-out.
// Args: ctx (used only for the initial connect), dsn (pooled Neon URL)
// Returns: shared *Store or the connect error, cached for the instance lifetime
func Shared(ctx context.Context, dsn string) (*Store, error) {
	sharedOnce.Do(func() {
		shared, sharedErr = Open(ctx, dsn)
	})
	return shared, sharedErr
}

// Open creates a pool configured for PgBouncer transaction pooling: the extended
// protocol's server-side prepared statements are unavailable there, so queries
// run in exec mode with statement caching disabled.
// Args: ctx, dsn (Postgres URL)
// Returns: *Store or a parse/connect error
func Open(ctx context.Context, dsn string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}
	cfg.MaxConns = 2
	cfg.MinConns = 0
	cfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeExec
	cfg.ConnConfig.StatementCacheCapacity = 0
	cfg.ConnConfig.DescriptionCacheCapacity = 0

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("open pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Pool() *pgxpool.Pool { return s.pool }

func (s *Store) Close() { s.pool.Close() }

// Ping reports database reachability for the health endpoint.
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// tx runs fn inside a transaction, rolling back on error or panic.
func (s *Store) tx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// isUniqueViolation reports whether err is a Postgres unique-constraint error,
// optionally narrowed to a specific constraint name.
func isUniqueViolation(err error, constraint string) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		return false
	}
	return constraint == "" || pgErr.ConstraintName == constraint
}

func noRows(err error) bool { return errors.Is(err, pgx.ErrNoRows) }
