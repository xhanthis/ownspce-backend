package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Run status is the only axis the UI branches on. pr_ready, failed and canceled
// are absorbing: the sole way out is a retry, which creates a new row.
const (
	RunStatusQueued   = "queued"
	RunStatusRunning  = "running"
	RunStatusPRReady  = "pr_ready"
	RunStatusFailed   = "failed"
	RunStatusCanceled = "canceled"
)

// Run phase is informational and drives the timeline only. It never moves
// backwards except on a requeue, and freezes where a run died so the timeline
// still shows how far it got.
const (
	RunPhaseQueued  = "queued"
	RunPhaseClaimed = "claimed"
	RunPhaseCloning = "cloning"
	RunPhaseCoding  = "coding"
	RunPhaseChecks  = "checks"
	RunPhasePushing = "pushing"
	RunPhasePR      = "pr"
)

// Run outcome explains a finished run. ok and canceled are server-set only.
const (
	RunOutcomeOK       = "ok"
	RunOutcomeAuth     = "auth"
	RunOutcomeQuota    = "quota"
	RunOutcomeMaxTurns = "max_turns"
	RunOutcomeDeadline = "deadline"
	RunOutcomeChecks   = "checks"
	RunOutcomeError    = "error"
	RunOutcomeCanceled = "canceled"
)

// RunMaxAttempts is the default retry ceiling stamped on a new row. It ships as
// data rather than a constant in the guards so it can be tuned per run.
const RunMaxAttempts = 3

// Run is one automation request and everything known about its progress.
type Run struct {
	ID            uuid.UUID
	UserID        uuid.UUID
	PageID        string
	TaskID        string
	TaskTitle     string
	Instructions  string
	Repo          string
	BaseBranch    string
	Branch        string
	Status        string
	Phase         string
	Attempts      int
	MaxAttempts   int
	Outcome       string
	PRURL         string
	ErrorLog      string
	ProgressLog   string
	TokensUsed    int64
	DaemonTokenID *uuid.UUID
	CreatedAt     time.Time
	StartedAt     *time.Time
	FinishedAt    *time.Time
	HeartbeatAt   *time.Time
	UpdatedAt     time.Time
}

// RunLifecycle is a run's state after a guarded write, which is all a daemon
// needs to decide whether to keep working. Accepted is false when the guard
// matched nothing, meaning the run was canceled, reclaimed or reassigned.
type RunLifecycle struct {
	Status      string
	Phase       string
	Attempts    int
	MaxAttempts int
	Accepted    bool
}

const runColumns = `id, user_id, page_id, task_id, task_title, instructions, repo, base_branch, branch, status, phase, attempts, max_attempts, outcome, pr_url, error_log, progress_log, tokens_used, daemon_token_id, created_at, started_at, finished_at, heartbeat_at, updated_at`

// runSummaryColumns substitutes empty literals for the two heavy columns so a
// single scanRun serves every query while list pages stay small: fifty rows of
// instructions on a five-second poll would be hundreds of kilobytes.
const runSummaryColumns = `id, user_id, page_id, task_id, task_title, '' AS instructions, repo, base_branch, branch, status, phase, attempts, max_attempts, outcome, pr_url, error_log, '' AS progress_log, tokens_used, daemon_token_id, created_at, started_at, finished_at, heartbeat_at, updated_at`

const runInsertColumns = `user_id, page_id, task_id, task_title, instructions, repo, base_branch, branch`

// reclaimZombieRuns requeues runs whose daemon stopped heartbeating, parking them
// once the retry ceiling is reached. Every SET expression reads the pre-update
// attempts, so attempts + 1 is the post-update value.
const reclaimZombieRuns = `UPDATE automation_runs SET attempts = attempts + 1, status = CASE WHEN attempts + 1 >= max_attempts THEN 'failed' ELSE 'queued' END, phase = CASE WHEN attempts + 1 >= max_attempts THEN phase ELSE 'queued' END, outcome = CASE WHEN attempts + 1 >= max_attempts THEN 'error' ELSE outcome END, error_log = CASE WHEN attempts + 1 >= max_attempts THEN 'the daemon stopped reporting for more than 10 minutes' ELSE error_log END, daemon_token_id = NULL, started_at = CASE WHEN attempts + 1 >= max_attempts THEN started_at ELSE NULL END, heartbeat_at = NULL, finished_at = CASE WHEN attempts + 1 >= max_attempts THEN now() ELSE NULL END, updated_at = now() WHERE status = 'running' AND heartbeat_at < now() - interval '10 minutes'`

const claimNextRun = `WITH candidate AS (SELECT id FROM automation_runs WHERE status = 'queued' AND user_id = $1 AND repo IN (SELECT full_name FROM daemon_repos WHERE daemon_token_id = $2) ORDER BY created_at ASC LIMIT 1 FOR UPDATE SKIP LOCKED) UPDATE automation_runs r SET status = 'running', phase = 'claimed', daemon_token_id = $2, started_at = now(), heartbeat_at = now(), finished_at = NULL, updated_at = now() FROM candidate c WHERE r.id = c.id RETURNING r.id, r.user_id, r.page_id, r.task_id, r.task_title, r.instructions, r.repo, r.base_branch, r.branch, r.status, r.phase, r.attempts, r.max_attempts, r.outcome, r.pr_url, r.error_log, r.progress_log, r.tokens_used, r.daemon_token_id, r.created_at, r.started_at, r.finished_at, r.heartbeat_at, r.updated_at`

func scanRun(row pgx.Row) (*Run, error) {
	var r Run
	if err := row.Scan(&r.ID, &r.UserID, &r.PageID, &r.TaskID, &r.TaskTitle, &r.Instructions, &r.Repo, &r.BaseBranch, &r.Branch, &r.Status, &r.Phase, &r.Attempts, &r.MaxAttempts, &r.Outcome, &r.PRURL, &r.ErrorLog, &r.ProgressLog, &r.TokensUsed, &r.DaemonTokenID, &r.CreatedAt, &r.StartedAt, &r.FinishedAt, &r.HeartbeatAt, &r.UpdatedAt); err != nil {
		if noRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &r, nil
}

// scanLifecycle reads a guarded lifecycle update. A guard that matched nothing is
// a conflict, not a missing row: the run exists but has left this daemon's hands.
func scanLifecycle(row pgx.Row) (*RunLifecycle, error) {
	var l RunLifecycle
	if err := row.Scan(&l.Status, &l.Attempts, &l.MaxAttempts); err != nil {
		if noRows(err) {
			return nil, ErrConflict
		}
		return nil, err
	}
	l.Accepted = true
	return &l, nil
}

// CreateRun queues a run. Branch is computed by the caller and stored, so every
// later claim of the same task lands on the same git ref.
// Args: ctx, r (user, page, task, title, instructions, repo and both branches)
// Returns: the stored run, error (ErrConflict when this task already has a queued
// or running row)
func (s *Store) CreateRun(ctx context.Context, r Run) (*Run, error) {
	run, err := scanRun(s.pool.QueryRow(ctx, "INSERT INTO automation_runs ("+runInsertColumns+") VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING "+runColumns, r.UserID, r.PageID, r.TaskID, r.TaskTitle, r.Instructions, r.Repo, r.BaseBranch, r.Branch))
	if isUniqueViolation(err, "uq_automation_runs_active") {
		return nil, ErrConflict
	}
	return run, err
}

// RetryRun queues a fresh run copying a finished one's payload. The source row is
// left untouched so the history of what was tried stays readable.
// Args: ctx, runID (the source), userID
// Returns: the new run, error (ErrNotFound when the source is absent or owned by
// someone else, ErrConflict when the task already has a live run)
func (s *Store) RetryRun(ctx context.Context, runID, userID uuid.UUID) (*Run, error) {
	run, err := scanRun(s.pool.QueryRow(ctx, "INSERT INTO automation_runs ("+runInsertColumns+") SELECT "+runInsertColumns+" FROM automation_runs WHERE id = $1 AND user_id = $2 RETURNING "+runColumns, runID, userID))
	if isUniqueViolation(err, "uq_automation_runs_active") {
		return nil, ErrConflict
	}
	return run, err
}

// GetRun loads one run with its instructions and progress log.
// Args: ctx, runID, userID
// Returns: run, error (ErrNotFound when unknown or owned by another user, which
// are deliberately indistinguishable)
func (s *Store) GetRun(ctx context.Context, runID, userID uuid.UUID) (*Run, error) {
	return scanRun(s.pool.QueryRow(ctx, "SELECT "+runColumns+" FROM automation_runs WHERE id = $1 AND user_id = $2", runID, userID))
}

// ListRuns pages a user's runs newest first, optionally narrowed to one page.
// The keyset predicate is spelled as an explicit OR rather than a row-value
// comparison so parameter types stay inferable under the exec query mode.
// Args: ctx, userID, pageID (empty for every page), limit, cursorAt and cursorID
// (both nil for the first page)
// Returns: runs with instructions and progressLog blanked, error
func (s *Store) ListRuns(ctx context.Context, userID uuid.UUID, pageID string, limit int, cursorAt *time.Time, cursorID *uuid.UUID) ([]Run, error) {
	const (
		listGlobal       = "SELECT " + runSummaryColumns + " FROM automation_runs WHERE user_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2"
		listGlobalCursor = "SELECT " + runSummaryColumns + " FROM automation_runs WHERE user_id = $1 AND (created_at < $3 OR (created_at = $3 AND id < $4)) ORDER BY created_at DESC, id DESC LIMIT $2"
		listPage         = "SELECT " + runSummaryColumns + " FROM automation_runs WHERE user_id = $1 AND page_id = $3 ORDER BY created_at DESC, id DESC LIMIT $2"
		listPageCursor   = "SELECT " + runSummaryColumns + " FROM automation_runs WHERE user_id = $1 AND page_id = $3 AND (created_at < $4 OR (created_at = $4 AND id < $5)) ORDER BY created_at DESC, id DESC LIMIT $2"
	)

	var (
		query string
		args  []any
	)
	switch {
	case pageID == "" && cursorAt == nil:
		query, args = listGlobal, []any{userID, limit}
	case pageID == "":
		query, args = listGlobalCursor, []any{userID, limit, *cursorAt, *cursorID}
	case cursorAt == nil:
		query, args = listPage, []any{userID, limit, pageID}
	default:
		query, args = listPageCursor, []any{userID, limit, pageID, *cursorAt, *cursorID}
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]Run, 0, limit)
	for rows.Next() {
		run, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *run)
	}
	return out, rows.Err()
}

// CancelRun terminates a live run at the user's request. The daemon learns within
// one heartbeat, because its next progress write loses the running guard.
// Args: ctx, runID, userID
// Returns: the canceled run, error (ErrNotFound when absent or owned by someone
// else, ErrConflict when it had already finished)
func (s *Store) CancelRun(ctx context.Context, runID, userID uuid.UUID) (*Run, error) {
	run, err := scanRun(s.pool.QueryRow(ctx, "UPDATE automation_runs SET status = 'canceled', outcome = 'canceled', finished_at = now(), updated_at = now() WHERE id = $1 AND user_id = $2 AND status IN ('queued','running') RETURNING "+runSummaryColumns, runID, userID))
	if !errors.Is(err, ErrNotFound) {
		return run, err
	}

	var exists bool
	if err := s.pool.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM automation_runs WHERE id = $1 AND user_id = $2)", runID, userID).Scan(&exists); err != nil {
		return nil, err
	}
	if exists {
		return nil, ErrConflict
	}
	return nil, ErrNotFound
}

// ClaimRun hands a daemon its next run. It first requeues runs abandoned by a
// dead daemon, then stamps this daemon's liveness, then takes the oldest queued
// run for a repo this daemon reported — so two daemons on one account covering
// different repos each get work they can actually clone. The three statements run
// unwrapped: each is atomic on its own, and the platform caps a request at ten
// seconds.
// Args: ctx, daemonID, userID (the daemon's owner)
// Returns: the claimed run, error (ErrNotFound when there is nothing to do)
func (s *Store) ClaimRun(ctx context.Context, daemonID, userID uuid.UUID) (*Run, error) {
	if _, err := s.pool.Exec(ctx, reclaimZombieRuns); err != nil {
		return nil, err
	}
	if _, err := s.pool.Exec(ctx, "UPDATE daemon_tokens SET last_seen_at = now() WHERE id = $1", daemonID); err != nil {
		return nil, err
	}
	return scanRun(s.pool.QueryRow(ctx, claimNextRun, userID, daemonID))
}

// SaveRunProgress records a heartbeat from the daemon that owns a run. This is
// also the cancel channel, so a lost guard is not an error: the current state is
// read back and returned with Accepted false, which tells the daemon to abort.
// Args: ctx, runID, daemonID, userID (the daemon's owner, scoping the fallback
// read), phase, progressLog (empty means no change), tokensUsed (monotonic)
// Returns: the run's state after the write, error (ErrNotFound when the run is
// unknown or belongs to another user)
func (s *Store) SaveRunProgress(ctx context.Context, runID, daemonID, userID uuid.UUID, phase, progressLog string, tokensUsed int64) (*RunLifecycle, error) {
	var l RunLifecycle
	err := s.pool.QueryRow(ctx, "UPDATE automation_runs SET phase = $3, progress_log = CASE WHEN $4 = '' THEN progress_log ELSE $4 END, tokens_used = GREATEST(tokens_used, $5), heartbeat_at = now(), updated_at = now() WHERE id = $1 AND daemon_token_id = $2 AND status = 'running' RETURNING status, phase, attempts, max_attempts", runID, daemonID, phase, progressLog, tokensUsed).Scan(&l.Status, &l.Phase, &l.Attempts, &l.MaxAttempts)
	if err == nil {
		l.Accepted = true
		return &l, nil
	}
	if !noRows(err) {
		return nil, err
	}

	if err := s.pool.QueryRow(ctx, "SELECT status, phase, attempts, max_attempts FROM automation_runs WHERE id = $1 AND user_id = $2", runID, userID).Scan(&l.Status, &l.Phase, &l.Attempts, &l.MaxAttempts); err != nil {
		if noRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &l, nil
}

// CompleteRun parks a run at pr_ready with the pull request the daemon opened.
// Args: ctx, runID, daemonID, prURL, tokensUsed
// Returns: the run's state after the write, error (ErrConflict when the run was
// canceled or reassigned while the daemon was working)
func (s *Store) CompleteRun(ctx context.Context, runID, daemonID uuid.UUID, prURL string, tokensUsed int64) (*RunLifecycle, error) {
	return scanLifecycle(s.pool.QueryRow(ctx, "UPDATE automation_runs SET status = 'pr_ready', phase = 'pr', outcome = 'ok', pr_url = $3, error_log = '', tokens_used = GREATEST(tokens_used, $4), heartbeat_at = now(), finished_at = now(), updated_at = now() WHERE id = $1 AND daemon_token_id = $2 AND status = 'running' RETURNING status, attempts, max_attempts", runID, daemonID, prURL, tokensUsed))
}

// FailRun reports a run the daemon could not finish. A park (an auth failure the
// user must fix by hand) goes straight to failed without burning an attempt;
// anything else spends one and requeues until the ceiling is reached.
// Args: ctx, runID, daemonID, outcome, errorLog (already truncated), tokensUsed,
// park (true only for an auth outcome)
// Returns: the run's state after the write, error (ErrConflict on a lost guard)
func (s *Store) FailRun(ctx context.Context, runID, daemonID uuid.UUID, outcome, errorLog string, tokensUsed int64, park bool) (*RunLifecycle, error) {
	return scanLifecycle(s.pool.QueryRow(ctx, "UPDATE automation_runs SET attempts = attempts + CASE WHEN $5 THEN 0 ELSE 1 END, status = CASE WHEN $5 OR attempts + 1 >= max_attempts THEN 'failed' ELSE 'queued' END, phase = CASE WHEN $5 OR attempts + 1 >= max_attempts THEN phase ELSE 'queued' END, outcome = $4, error_log = $3, daemon_token_id = CASE WHEN $5 OR attempts + 1 >= max_attempts THEN daemon_token_id ELSE NULL END, started_at = CASE WHEN $5 OR attempts + 1 >= max_attempts THEN started_at ELSE NULL END, heartbeat_at = NULL, finished_at = CASE WHEN $5 OR attempts + 1 >= max_attempts THEN now() ELSE NULL END, tokens_used = GREATEST(tokens_used, $6), updated_at = now() WHERE id = $1 AND daemon_token_id = $2 AND status = 'running' RETURNING status, attempts, max_attempts", runID, daemonID, errorLog, outcome, park, tokensUsed))
}

// ReleaseRun hands a run back unfinished because the daemon ran out of quota or
// time. No attempt is spent — nothing was wrong with the work — and the progress
// log survives so the next claim resumes from real progress.
// Args: ctx, runID, daemonID, outcome, errorLog (already truncated), tokensUsed
// Returns: the run's state after the write, error (ErrConflict on a lost guard)
func (s *Store) ReleaseRun(ctx context.Context, runID, daemonID uuid.UUID, outcome, errorLog string, tokensUsed int64) (*RunLifecycle, error) {
	return scanLifecycle(s.pool.QueryRow(ctx, "UPDATE automation_runs SET status = 'queued', phase = 'queued', outcome = $4, error_log = $3, daemon_token_id = NULL, started_at = NULL, heartbeat_at = NULL, finished_at = NULL, tokens_used = GREATEST(tokens_used, $5), updated_at = now() WHERE id = $1 AND daemon_token_id = $2 AND status = 'running' RETURNING status, attempts, max_attempts", runID, daemonID, errorLog, outcome, tokensUsed))
}
