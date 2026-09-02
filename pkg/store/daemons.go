package store

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// DaemonTokenPrefix marks a daemon bearer, so the middleware can tell a daemon
// credential from a user JWT before it costs a database round trip.
const DaemonTokenPrefix = "ospd_"

// Daemon is a paired local agent. The plaintext token exists only in the
// MintDaemonToken return value; every later read is by SHA-256.
type Daemon struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	Name       string
	Version    string
	CreatedAt  time.Time
	LastSeenAt *time.Time
	Plaintext  string
}

// Repo is a repository a daemon reported it can clone and push to. It is also
// the connected-repo allowlist: a run may only name a repo some live daemon of
// the same account has reported.
type Repo struct {
	FullName      string
	DefaultBranch string
}

const daemonColumns = `id, user_id, name, version, created_at, last_seen_at`

func scanDaemon(row pgx.Row) (*Daemon, error) {
	var d Daemon
	if err := row.Scan(&d.ID, &d.UserID, &d.Name, &d.Version, &d.CreatedAt, &d.LastSeenAt); err != nil {
		if noRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &d, nil
}

// MintDaemonToken issues a credential for a new daemon. Only the SHA-256 of the
// prefixed plaintext is stored, so a database leak yields no usable tokens and
// the plaintext can never be recovered after this call returns.
// Args: ctx, userID, name (the label shown in settings)
// Returns: daemon with Plaintext set, error
func (s *Store) MintDaemonToken(ctx context.Context, userID uuid.UUID, name string) (*Daemon, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("generate daemon token: %w", err)
	}
	plaintext := DaemonTokenPrefix + base64.RawURLEncoding.EncodeToString(raw)

	d := &Daemon{UserID: userID, Name: name, Plaintext: plaintext}
	if err := s.pool.QueryRow(ctx, "INSERT INTO daemon_tokens (user_id, name, token_hash) VALUES ($1, $2, $3) RETURNING id, created_at", userID, name, hashToken(plaintext)).Scan(&d.ID, &d.CreatedAt); err != nil {
		return nil, err
	}
	return d, nil
}

// DaemonByToken resolves a presented bearer to its live daemon row, which is what
// makes revocation take effect on the daemon's very next request.
// Args: ctx, plaintext (the full prefixed token, hashed here — never stripped)
// Returns: daemon, error (ErrNotFound when unknown or revoked)
func (s *Store) DaemonByToken(ctx context.Context, plaintext string) (*Daemon, error) {
	return scanDaemon(s.pool.QueryRow(ctx, "SELECT "+daemonColumns+" FROM daemon_tokens WHERE token_hash = $1 AND revoked_at IS NULL", hashToken(plaintext)))
}

// ListDaemons returns a user's live daemons together with the repos each one
// reported, in two queries rather than one per daemon.
// Args: ctx, userID
// Returns: daemons oldest first, their repos keyed by daemon id, error
func (s *Store) ListDaemons(ctx context.Context, userID uuid.UUID) ([]Daemon, map[uuid.UUID][]Repo, error) {
	rows, err := s.pool.Query(ctx, "SELECT "+daemonColumns+" FROM daemon_tokens WHERE user_id = $1 AND revoked_at IS NULL ORDER BY created_at ASC", userID)
	if err != nil {
		return nil, nil, err
	}
	var daemons []Daemon
	for rows.Next() {
		var d Daemon
		if err := rows.Scan(&d.ID, &d.UserID, &d.Name, &d.Version, &d.CreatedAt, &d.LastSeenAt); err != nil {
			rows.Close()
			return nil, nil, err
		}
		daemons = append(daemons, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	repoRows, err := s.pool.Query(ctx, "SELECT dr.daemon_token_id, dr.full_name, dr.default_branch FROM daemon_repos dr JOIN daemon_tokens dt ON dt.id = dr.daemon_token_id WHERE dt.user_id = $1 AND dt.revoked_at IS NULL ORDER BY dr.full_name ASC", userID)
	if err != nil {
		return nil, nil, err
	}
	defer repoRows.Close()

	repos := make(map[uuid.UUID][]Repo, len(daemons))
	for repoRows.Next() {
		var daemonID uuid.UUID
		var repo Repo
		if err := repoRows.Scan(&daemonID, &repo.FullName, &repo.DefaultBranch); err != nil {
			return nil, nil, err
		}
		repos[daemonID] = append(repos[daemonID], repo)
	}
	return daemons, repos, repoRows.Err()
}

// ConnectedRepos is the deduplicated union of every live daemon's repos — exactly
// the list the web repo picker renders. On a duplicate name the oldest daemon
// supplies the default branch.
// Args: ctx, userID
// Returns: repos ordered by full name, error
func (s *Store) ConnectedRepos(ctx context.Context, userID uuid.UUID) ([]Repo, error) {
	rows, err := s.pool.Query(ctx, "SELECT DISTINCT ON (dr.full_name) dr.full_name, dr.default_branch FROM daemon_repos dr JOIN daemon_tokens dt ON dt.id = dr.daemon_token_id WHERE dt.user_id = $1 AND dt.revoked_at IS NULL ORDER BY dr.full_name ASC, dt.created_at ASC", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Repo
	for rows.Next() {
		var repo Repo
		if err := rows.Scan(&repo.FullName, &repo.DefaultBranch); err != nil {
			return nil, err
		}
		out = append(out, repo)
	}
	return out, rows.Err()
}

// RepoDefaultBranch resolves a repo against the user's live daemons, which is both
// the connected-repo check for queueing a run and the source of the base branch
// when the client did not name one.
// Args: ctx, userID, fullName
// Returns: default branch reported by the oldest daemon covering the repo, error
// (ErrForbidden when no live daemon reports it)
func (s *Store) RepoDefaultBranch(ctx context.Context, userID uuid.UUID, fullName string) (string, error) {
	var branch string
	if err := s.pool.QueryRow(ctx, "SELECT dr.default_branch FROM daemon_repos dr JOIN daemon_tokens dt ON dt.id = dr.daemon_token_id WHERE dt.user_id = $1 AND dt.revoked_at IS NULL AND dr.full_name = $2 ORDER BY dt.created_at ASC LIMIT 1", userID, fullName).Scan(&branch); err != nil {
		if noRows(err) {
			return "", ErrForbidden
		}
		return "", err
	}
	return branch, nil
}

// ReplaceDaemonRepos records a daemon check-in: it refreshes the label, version
// and liveness stamp, then swaps in the repo set the daemon just reported.
// Args: ctx, daemonID, name (empty keeps the stored name so the mint-time label
// wins), version, repos (replaces the whole set)
// Returns: error
func (s *Store) ReplaceDaemonRepos(ctx context.Context, daemonID uuid.UUID, name, version string, repos []Repo) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "UPDATE daemon_tokens SET name = CASE WHEN $2 = '' THEN name ELSE $2 END, version = $3, last_seen_at = now() WHERE id = $1", daemonID, name, version); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "DELETE FROM daemon_repos WHERE daemon_token_id = $1", daemonID); err != nil {
			return err
		}
		if len(repos) == 0 {
			return nil
		}

		batch := &pgx.Batch{}
		for _, repo := range repos {
			batch.Queue("INSERT INTO daemon_repos (daemon_token_id, full_name, default_branch) VALUES ($1, $2, $3)", daemonID, repo.FullName, repo.DefaultBranch)
		}
		results := tx.SendBatch(ctx, batch)
		for range repos {
			if _, err := results.Exec(); err != nil {
				results.Close()
				return err
			}
		}
		return results.Close()
	})
}

// RevokeDaemon retires a daemon and drops the repos it reported, so its next
// request fails auth and its repos stop satisfying the connected-repo check. Runs
// it owns are deliberately left alone: run history is never destroyed, and
// anything still in flight is requeued by the zombie reclaim.
// Args: ctx, userID, daemonID
// Returns: error (ErrNotFound when absent or owned by someone else)
// Handles: already revoked (no-op success, matching RevokeDevice)
func (s *Store) RevokeDaemon(ctx context.Context, userID, daemonID uuid.UUID) error {
	return s.tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, "UPDATE daemon_tokens SET revoked_at = now() WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL", daemonID, userID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			var exists bool
			if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM daemon_tokens WHERE id = $1 AND user_id = $2)", daemonID, userID).Scan(&exists); err != nil {
				return err
			}
			if !exists {
				return ErrNotFound
			}
			return nil
		}
		_, err = tx.Exec(ctx, "DELETE FROM daemon_repos WHERE daemon_token_id = $1", daemonID)
		return err
	})
}
