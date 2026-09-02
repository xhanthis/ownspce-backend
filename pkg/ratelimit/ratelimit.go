// Package ratelimit implements a fixed-window limiter in Postgres. The fixed
// stack has no Redis/KV, and serverless handlers keep no state between requests,
// so the window counter lives in a table keyed by subject and window start.
package ratelimit

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Limiter struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Limiter { return &Limiter{pool: pool} }

// Rule is a limit of Max events per Window for one bucket.
type Rule struct {
	Name   string
	Max    int
	Window time.Duration
}

// Predefined rules. Poll limits assume a 1-2s active poll plus reconnect bursts.
var (
	AuthSession    = Rule{Name: "auth_session", Max: 10, Window: time.Minute}
	AuthRefresh    = Rule{Name: "auth_refresh", Max: 30, Window: time.Minute}
	SyncPull       = Rule{Name: "sync_pull", Max: 120, Window: time.Minute}
	SyncPush       = Rule{Name: "sync_push", Max: 60, Window: time.Minute}
	SnapshotWrite  = Rule{Name: "snapshot_write", Max: 6, Window: time.Hour}
	KeyDirectory   = Rule{Name: "key_directory", Max: 60, Window: time.Minute}
	SpaceWrite     = Rule{Name: "space_write", Max: 60, Window: time.Minute}
	PublishWrite   = Rule{Name: "publish_write", Max: 5, Window: time.Hour}
	PublicRead     = Rule{Name: "public_read", Max: 300, Window: time.Minute}
	ProfileWrite   = Rule{Name: "profile_write", Max: 20, Window: time.Minute}
	DeviceRegister = Rule{Name: "device_register", Max: 10, Window: time.Hour}

	AutomationWrite = Rule{Name: "automation_write", Max: 30, Window: time.Hour}
	AutomationRead  = Rule{Name: "automation_read", Max: 240, Window: time.Minute}
	DaemonPoll      = Rule{Name: "daemon_poll", Max: 120, Window: time.Minute}
	DaemonMint      = Rule{Name: "daemon_mint", Max: 5, Window: time.Hour}
)

// Result reports the outcome of an allowance check.
type Result struct {
	Allowed    bool
	Remaining  int
	RetryAfter time.Duration
}

// Allow consumes one unit from the (rule, subject) bucket for the current window.
// Args: ctx, rule, subject (user id, device id, or client IP)
// Returns: result with remaining allowance and retry hint; a database error is
// returned to the caller, which fails open so a limiter outage cannot take the
// whole API down
// Handles: first request in a window, concurrent increments (atomic upsert)
func (l *Limiter) Allow(ctx context.Context, rule Rule, subject string) (Result, error) {
	now := time.Now().UTC()
	windowStart := now.Truncate(rule.Window)
	key := fmt.Sprintf("%s:%s", rule.Name, subject)

	var count int
	if err := l.pool.QueryRow(ctx, "INSERT INTO rate_limits (bucket_key, window_start, count) VALUES ($1, $2, 1) ON CONFLICT (bucket_key, window_start) DO UPDATE SET count = rate_limits.count + 1 RETURNING count", key, windowStart).Scan(&count); err != nil {
		return Result{Allowed: true}, err
	}

	if count > rule.Max {
		return Result{Allowed: false, Remaining: 0, RetryAfter: windowStart.Add(rule.Window).Sub(now)}, nil
	}
	return Result{Allowed: true, Remaining: rule.Max - count}, nil
}

// Sweep deletes expired windows. Called opportunistically (roughly 1% of
// requests) so no cron job is needed on a serverless platform.
func (l *Limiter) Sweep(ctx context.Context) error {
	_, err := l.pool.Exec(ctx, "DELETE FROM rate_limits WHERE window_start < now() - interval '2 hours'")
	return err
}

// Share and attachment writes are per-user and deliberately generous compared to
// publishing: attaching files is ordinary editing, not a public act.
var (
	ShareWrite      = Rule{Name: "share_write", Max: 60, Window: time.Hour}
	AttachmentWrite = Rule{Name: "attachment_write", Max: 120, Window: time.Hour}
)
