package httpapi

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/ownspce/backend/pkg/store"
)

// Automation field budgets, in UTF-8 bytes, matching the column CHECKs so a bad
// value is a clear 400 rather than a constraint violation surfacing as a 500.
const (
	maxPageIDBytes        = 64
	maxTaskIDBytes        = 64
	maxTaskTitleBytes     = 500
	maxInstructionsBytes  = 8000
	maxBranchBytes        = 255
	maxDaemonNameBytes    = 80
	maxDaemonVersionBytes = 40
	maxDaemonRepos        = 50
	maxPRURLBytes         = 500
	maxProgressLogBytes   = 16384
	maxErrorLogBytes      = 2000

	defaultRunListLimit = 50
	maxRunListLimit     = 100

	// daemonOnlineWindow is how long after its last check-in a daemon still counts
	// as online. A five-second claim poll keeps this comfortably fresh.
	daemonOnlineWindow = 120 * time.Second
)

var (
	repoPattern   = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}/[A-Za-z0-9._-]{1,100}$`)
	prURLPattern  = regexp.MustCompile(`^https://github\.com/[A-Za-z0-9._-]{1,100}/[A-Za-z0-9._-]{1,100}/pull/[0-9]{1,12}$`)
	cursorPattern = regexp.MustCompile(`^\d{1,19}\.[0-9a-f-]{36}$`)
)

type runPayload struct {
	ID          string  `json:"id"`
	PageID      string  `json:"pageId"`
	TaskID      string  `json:"taskId"`
	TaskTitle   string  `json:"taskTitle"`
	Repo        string  `json:"repo"`
	BaseBranch  string  `json:"baseBranch"`
	Branch      string  `json:"branch"`
	Status      string  `json:"status"`
	Phase       string  `json:"phase"`
	Attempts    int     `json:"attempts"`
	MaxAttempts int     `json:"maxAttempts"`
	Outcome     string  `json:"outcome"`
	PRURL       string  `json:"prUrl"`
	ErrorLog    string  `json:"errorLog"`
	TokensUsed  int64   `json:"tokensUsed"`
	DaemonID    *string `json:"daemonId"`
	CreatedAt   string  `json:"createdAt"`
	StartedAt   *string `json:"startedAt"`
	FinishedAt  *string `json:"finishedAt"`
	HeartbeatAt *string `json:"heartbeatAt"`
	UpdatedAt   string  `json:"updatedAt"`
}

// runDetailPayload adds the two heavy fields list responses omit. The embedded
// struct's exported fields are promoted, so this still serialises flat.
type runDetailPayload struct {
	runPayload
	Instructions string `json:"instructions"`
	ProgressLog  string `json:"progressLog"`
}

type repoPayload struct {
	FullName      string `json:"fullName"`
	DefaultBranch string `json:"defaultBranch"`
}

type daemonPayload struct {
	ID         string        `json:"id"`
	Name       string        `json:"name"`
	Version    string        `json:"version"`
	CreatedAt  string        `json:"createdAt"`
	LastSeenAt *string       `json:"lastSeenAt"`
	Online     bool          `json:"online"`
	Repos      []repoPayload `json:"repos"`
}

type queueRunRequest struct {
	PageID       string `json:"pageId"`
	TaskID       string `json:"taskId"`
	TaskTitle    string `json:"taskTitle"`
	Instructions string `json:"instructions"`
	Repo         string `json:"repo"`
	BaseBranch   string `json:"baseBranch"`
}

type mintDaemonRequest struct {
	Name string `json:"name"`
}

// formatNullableTime renders an optional timestamp as RFC3339 or JSON null, never
// as an empty string, which clients would have to special-case.
func formatNullableTime(t *time.Time) *string {
	if t == nil {
		return nil
	}
	formatted := t.UTC().Format(time.RFC3339)
	return &formatted
}

func toRunPayload(r store.Run) runPayload {
	var daemonID *string
	if r.DaemonTokenID != nil {
		id := r.DaemonTokenID.String()
		daemonID = &id
	}
	return runPayload{ID: r.ID.String(), PageID: r.PageID, TaskID: r.TaskID, TaskTitle: r.TaskTitle, Repo: r.Repo, BaseBranch: r.BaseBranch, Branch: r.Branch, Status: r.Status, Phase: r.Phase, Attempts: r.Attempts, MaxAttempts: r.MaxAttempts, Outcome: r.Outcome, PRURL: r.PRURL, ErrorLog: r.ErrorLog, TokensUsed: r.TokensUsed, DaemonID: daemonID, CreatedAt: r.CreatedAt.UTC().Format(time.RFC3339), StartedAt: formatNullableTime(r.StartedAt), FinishedAt: formatNullableTime(r.FinishedAt), HeartbeatAt: formatNullableTime(r.HeartbeatAt), UpdatedAt: r.UpdatedAt.UTC().Format(time.RFC3339)}
}

func toRunDetailPayload(r store.Run) runDetailPayload {
	return runDetailPayload{runPayload: toRunPayload(r), Instructions: r.Instructions, ProgressLog: r.ProgressLog}
}

func toRepoPayloads(repos []store.Repo) []repoPayload {
	out := make([]repoPayload, 0, len(repos))
	for _, repo := range repos {
		out = append(out, repoPayload{FullName: repo.FullName, DefaultBranch: repo.DefaultBranch})
	}
	return out
}

// toDaemonPayloads renders a user's daemons with their repos and server-computed
// liveness. Clients must not recompute online: only the server knows the window.
func toDaemonPayloads(daemons []store.Daemon, repos map[uuid.UUID][]store.Repo, now time.Time) []daemonPayload {
	out := make([]daemonPayload, 0, len(daemons))
	for _, d := range daemons {
		out = append(out, daemonPayload{ID: d.ID.String(), Name: d.Name, Version: d.Version, CreatedAt: d.CreatedAt.UTC().Format(time.RFC3339), LastSeenAt: formatNullableTime(d.LastSeenAt), Online: d.LastSeenAt != nil && now.Sub(*d.LastSeenAt) < daemonOnlineWindow, Repos: toRepoPayloads(repos[d.ID])})
	}
	return out
}

// checkText validates one free-text wire field against its byte budget.
// Args: value (already trimmed by the caller when the field trims), field (the
// name used in the message), minBytes, maxBytes
// Returns: a 400 when the value is missing, oversized, or carries a NUL byte,
// which a Postgres text column cannot store
func checkText(value, field string, minBytes, maxBytes int) error {
	if strings.ContainsRune(value, 0) {
		return badRequest("%s must not contain a NUL byte", field)
	}
	if len(value) < minBytes {
		return badRequest("%s is required", field)
	}
	if len(value) > maxBytes {
		return badRequest("%s must be at most %d bytes", field, maxBytes)
	}
	return nil
}

// firstError returns the first failure from a field check list, so a handler can
// validate a whole request body in one statement.
func firstError(checks ...error) error {
	for _, err := range checks {
		if err != nil {
			return err
		}
	}
	return nil
}

// tailBytes returns the last max bytes of s, advanced forward to the next UTF-8
// rune boundary so the result is always valid UTF-8.
// Args: s (the log), max (byte budget)
// Returns: s unchanged when it already fits, otherwise its tail
func tailBytes(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := s[len(s)-max:]
	for i := 0; i < len(cut); i++ {
		if utf8.RuneStart(cut[i]) {
			return cut[i:]
		}
	}
	return ""
}

// branchFor derives the git branch a task's work lands on, computed once at queue
// time and stored so every later claim resumes the same ref. The digest is taken
// over the raw task id, not the sanitized head, so two ids sharing their first
// eight characters cannot collide onto one branch and one pull request.
// Args: taskID (exactly as the client sent it)
// Returns: a branch matching ^ownspce/task-[a-z0-9-]{1,8}-[0-9a-f]{6}$
func branchFor(taskID string) string {
	sanitized := make([]byte, 0, len(taskID))
	for i := 0; i < len(taskID); i++ {
		c := taskID[i]
		switch {
		case c >= 'A' && c <= 'Z':
			c += 'a' - 'A'
		case (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'):
		default:
			c = '-'
		}
		if c == '-' && (len(sanitized) == 0 || sanitized[len(sanitized)-1] == '-') {
			continue
		}
		sanitized = append(sanitized, c)
	}

	head := strings.TrimRight(string(sanitized), "-")
	if len(head) > 8 {
		head = strings.TrimRight(head[:8], "-")
	}
	if head == "" {
		head = "task"
	}
	digest := sha256.Sum256([]byte(taskID))
	return fmt.Sprintf("ownspce/task-%s-%x", head, digest[:3])
}

// encodeRunCursor builds the opaque keyset cursor from the last row of a page.
// Microseconds match the column's precision, so the value round-trips exactly.
func encodeRunCursor(r store.Run) string {
	return fmt.Sprintf("%d.%s", r.CreatedAt.UnixMicro(), r.ID)
}

// decodeRunCursor parses a cursor the client echoed back.
// Args: raw (a nextCursor from a previous page)
// Returns: the created-at and id halves, error (a 400 when malformed — silently
// ignoring a bad cursor would restart the list and loop the UI forever)
func decodeRunCursor(raw string) (time.Time, uuid.UUID, error) {
	if !cursorPattern.MatchString(raw) {
		return time.Time{}, uuid.Nil, badRequest("cursor is malformed")
	}
	micros, rawID, _ := strings.Cut(raw, ".")
	at, err := strconv.ParseInt(micros, 10, 64)
	if err != nil {
		return time.Time{}, uuid.Nil, badRequest("cursor is malformed")
	}
	id, err := uuid.Parse(rawID)
	if err != nil {
		return time.Time{}, uuid.Nil, badRequest("cursor is malformed")
	}
	return time.UnixMicro(at).UTC(), id, nil
}

// handleQueueRun queues one task for a daemon to work on. The repo must already
// be reported by a live daemon of this account, which is both the routing check
// and the reason an unpaired user cannot queue work that would never run.
// Handles: unconnected repo (403), a task that already has a run in flight (409),
// an empty baseBranch (filled from the connected repo's default).
func (s *Server) handleQueueRun(w http.ResponseWriter, r *http.Request) {
	var req queueRunRequest
	if err := decodeJSON(w, r, maxSmallBody, &req); err != nil {
		writeError(w, err)
		return
	}

	run := store.Run{
		PageID:       strings.TrimSpace(req.PageID),
		TaskID:       strings.TrimSpace(req.TaskID),
		TaskTitle:    strings.TrimSpace(req.TaskTitle),
		Instructions: req.Instructions,
		Repo:         strings.TrimSpace(req.Repo),
		BaseBranch:   strings.TrimSpace(req.BaseBranch),
	}
	if err := firstError(
		checkText(run.PageID, "pageId", 1, maxPageIDBytes),
		checkText(run.TaskID, "taskId", 1, maxTaskIDBytes),
		checkText(run.TaskTitle, "taskTitle", 0, maxTaskTitleBytes),
		checkText(run.Instructions, "instructions", 0, maxInstructionsBytes),
		checkText(run.BaseBranch, "baseBranch", 0, maxBranchBytes),
	); err != nil {
		writeError(w, err)
		return
	}
	if !repoPattern.MatchString(run.Repo) {
		writeError(w, badRequest("repo must be owner/name using letters, digits, dot, dash or underscore"))
		return
	}

	run.UserID = callerFrom(r.Context()).UserID
	defaultBranch, err := s.store.RepoDefaultBranch(r.Context(), run.UserID, run.Repo)
	if err != nil {
		writeError(w, storeError(err, "no such run", "", "", "repo_not_connected", "no connected daemon reports that repository"))
		return
	}
	if run.BaseBranch == "" {
		run.BaseBranch = defaultBranch
	}
	run.Branch = branchFor(run.TaskID)

	created, err := s.store.CreateRun(r.Context(), run)
	if err != nil {
		writeError(w, storeError(err, "no such run", "run_active", "this task already has a run in flight", "", ""))
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"run": toRunDetailPayload(*created)})
}

// handleListRuns pages a user's runs newest first, across every page by default
// and narrowed to one page when pageId is given. A malformed limit falls back to
// the default rather than erroring, matching the rest of the API; a malformed
// cursor is rejected, because silently restarting would loop the caller.
func (s *Server) handleListRuns(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	pageID := strings.TrimSpace(query.Get("pageId"))
	if pageID != "" {
		if err := checkText(pageID, "pageId", 1, maxPageIDBytes); err != nil {
			writeError(w, err)
			return
		}
	}

	limit := defaultRunListLimit
	if parsed, err := strconv.Atoi(query.Get("limit")); err == nil && parsed >= 1 {
		limit = min(parsed, maxRunListLimit)
	}

	var (
		cursorAt *time.Time
		cursorID *uuid.UUID
	)
	if raw := query.Get("cursor"); raw != "" {
		at, id, err := decodeRunCursor(raw)
		if err != nil {
			writeError(w, err)
			return
		}
		cursorAt, cursorID = &at, &id
	}

	runs, err := s.store.ListRuns(r.Context(), callerFrom(r.Context()).UserID, pageID, limit, cursorAt, cursorID)
	if err != nil {
		writeError(w, err)
		return
	}

	out := make([]runPayload, 0, len(runs))
	for _, run := range runs {
		out = append(out, toRunPayload(run))
	}
	var nextCursor *string
	if len(runs) == limit {
		cursor := encodeRunCursor(runs[len(runs)-1])
		nextCursor = &cursor
	}
	writeJSON(w, http.StatusOK, map[string]any{"runs": out, "nextCursor": nextCursor})
}

func (s *Server) handleGetRun(w http.ResponseWriter, r *http.Request) {
	runID, err := parseUUIDParam(chi.URLParam(r, "runID"), "runId")
	if err != nil {
		writeError(w, err)
		return
	}

	run, err := s.store.GetRun(r.Context(), runID, callerFrom(r.Context()).UserID)
	if err != nil {
		writeError(w, storeError(err, "no such run", "", "", "", ""))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"run": toRunDetailPayload(*run)})
}

// handleCancelRun stops a queued or running run. A run that already finished is a
// conflict rather than a no-op, so the UI can tell the user nothing changed.
func (s *Server) handleCancelRun(w http.ResponseWriter, r *http.Request) {
	runID, err := parseUUIDParam(chi.URLParam(r, "runID"), "runId")
	if err != nil {
		writeError(w, err)
		return
	}

	run, err := s.store.CancelRun(r.Context(), runID, callerFrom(r.Context()).UserID)
	if err != nil {
		writeError(w, storeError(err, "no such run", "run_not_active", "this run has already finished", "", ""))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"run": toRunPayload(*run)})
}

// handleRetryRun queues a fresh run from a finished one's payload. The source row
// is preserved so the record of what was already tried survives the retry.
func (s *Server) handleRetryRun(w http.ResponseWriter, r *http.Request) {
	runID, err := parseUUIDParam(chi.URLParam(r, "runID"), "runId")
	if err != nil {
		writeError(w, err)
		return
	}

	run, err := s.store.RetryRun(r.Context(), runID, callerFrom(r.Context()).UserID)
	if err != nil {
		writeError(w, storeError(err, "no such run", "run_active", "this task already has a run in flight", "", ""))
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"run": toRunDetailPayload(*run)})
}

// handleAutomationStatus answers everything the automate dialog needs in one call:
// whether any daemon is reachable, which machines are paired, and the union of
// repos they can work on.
func (s *Server) handleAutomationStatus(w http.ResponseWriter, r *http.Request) {
	userID := callerFrom(r.Context()).UserID
	daemons, repos, err := s.store.ListDaemons(r.Context(), userID)
	if err != nil {
		writeError(w, err)
		return
	}
	connected, err := s.store.ConnectedRepos(r.Context(), userID)
	if err != nil {
		writeError(w, err)
		return
	}

	payloads := toDaemonPayloads(daemons, repos, time.Now())
	online := false
	for _, d := range payloads {
		if d.Online {
			online = true
			break
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"online": online, "daemons": payloads, "repos": toRepoPayloads(connected)})
}

// handleMintDaemon issues a pairing token for a new machine. The plaintext is
// returned exactly once and is never recoverable, so the client must show it in a
// one-time reveal.
func (s *Server) handleMintDaemon(w http.ResponseWriter, r *http.Request) {
	var req mintDaemonRequest
	if err := decodeJSON(w, r, maxSmallBody, &req); err != nil {
		writeError(w, err)
		return
	}

	name := strings.TrimSpace(req.Name)
	if err := checkText(name, "name", 1, maxDaemonNameBytes); err != nil {
		writeError(w, err)
		return
	}

	daemon, err := s.store.MintDaemonToken(r.Context(), callerFrom(r.Context()).UserID, name)
	if err != nil {
		writeError(w, err)
		return
	}
	payload := daemonPayload{ID: daemon.ID.String(), Name: daemon.Name, Version: daemon.Version, CreatedAt: daemon.CreatedAt.UTC().Format(time.RFC3339), LastSeenAt: nil, Online: false, Repos: []repoPayload{}}
	writeJSON(w, http.StatusCreated, map[string]any{"token": daemon.Plaintext, "daemon": payload})
}

func (s *Server) handleListDaemons(w http.ResponseWriter, r *http.Request) {
	daemons, repos, err := s.store.ListDaemons(r.Context(), callerFrom(r.Context()).UserID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"daemons": toDaemonPayloads(daemons, repos, time.Now())})
}

// handleRevokeDaemon unpairs a machine. Runs it owns are left in place — history
// is never destroyed — and anything still in flight is requeued by the zombie
// reclaim within ten minutes.
func (s *Server) handleRevokeDaemon(w http.ResponseWriter, r *http.Request) {
	daemonID, err := parseUUIDParam(chi.URLParam(r, "daemonID"), "daemonId")
	if err != nil {
		writeError(w, err)
		return
	}

	if err := s.store.RevokeDaemon(r.Context(), callerFrom(r.Context()).UserID, daemonID); err != nil {
		writeError(w, storeError(err, "no such daemon", "", "", "", ""))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
