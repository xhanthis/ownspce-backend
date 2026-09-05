package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/ownspce/backend/pkg/store"
)

type daemonRegisterRequest struct {
	Name    string        `json:"name"`
	Version string        `json:"version"`
	Repos   []repoPayload `json:"repos"`
}

type daemonProgressRequest struct {
	Phase       string `json:"phase"`
	ProgressLog string `json:"progressLog"`
	TokensUsed  int64  `json:"tokensUsed"`
}

type daemonCompleteRequest struct {
	PRURL      string `json:"prUrl"`
	TokensUsed int64  `json:"tokensUsed"`
}

// daemonOutcomeRequest is shared by fail and release; the outcomes each accepts
// differ, which is what decides whether an attempt is spent.
type daemonOutcomeRequest struct {
	Outcome    string `json:"outcome"`
	ErrorLog   string `json:"errorLog"`
	TokensUsed int64  `json:"tokensUsed"`
}

// writeLifecycle renders the response every terminal daemon write returns.
func writeLifecycle(w http.ResponseWriter, l store.RunLifecycle) {
	writeJSON(w, http.StatusOK, map[string]any{"status": l.Status, "attempts": l.Attempts, "maxAttempts": l.MaxAttempts})
}

// decodeOutcomeRequest reads and validates a fail or release body against the
// outcome vocabulary that endpoint accepts, so a daemon cannot claim an outcome
// only the server may set.
// Args: w, r, allowed (the outcomes this endpoint permits)
// Returns: the decoded body with errorLog truncated to its stored budget, error
func decodeOutcomeRequest(w http.ResponseWriter, r *http.Request, allowed ...string) (daemonOutcomeRequest, error) {
	var req daemonOutcomeRequest
	if err := decodeJSON(w, r, maxSmallBody, &req); err != nil {
		return req, err
	}
	if !oneOf(req.Outcome, allowed...) {
		return req, badRequest("outcome must be one of %s", strings.Join(allowed, ", "))
	}
	if req.TokensUsed < 0 {
		return req, badRequest("tokensUsed must not be negative")
	}
	if strings.ContainsRune(req.ErrorLog, 0) {
		return req, badRequest("errorLog must not contain a NUL byte")
	}
	req.ErrorLog = tailBytes(req.ErrorLog, maxErrorLogBytes)
	return req, nil
}

// handleDaemonRegister records a daemon check-in: its label, its version, and the
// repos it can clone. The repo set is replaced wholesale, so removing a repo from
// the daemon's config stops new runs routing to it on the next check-in.
// Handles: an empty name (keeps the mint-time label), a duplicate repo in one
// payload (400 — last-wins would silently pick a branch the user did not mean).
func (s *Server) handleDaemonRegister(w http.ResponseWriter, r *http.Request) {
	var req daemonRegisterRequest
	if err := decodeJSON(w, r, maxSmallBody, &req); err != nil {
		writeError(w, err)
		return
	}

	name := strings.TrimSpace(req.Name)
	if err := firstError(
		checkText(name, "name", 0, maxDaemonNameBytes),
		checkText(req.Version, "version", 0, maxDaemonVersionBytes),
	); err != nil {
		writeError(w, err)
		return
	}
	if len(req.Repos) > maxDaemonRepos {
		writeError(w, badRequest("repos must hold at most %d entries", maxDaemonRepos))
		return
	}

	repos := make([]store.Repo, 0, len(req.Repos))
	seen := make(map[string]bool, len(req.Repos))
	for _, repo := range req.Repos {
		if !repoPattern.MatchString(repo.FullName) {
			writeError(w, badRequest("repos[].fullName must be owner/name using letters, digits, dot, dash or underscore"))
			return
		}
		if err := checkText(repo.DefaultBranch, "repos[].defaultBranch", 1, maxBranchBytes); err != nil {
			writeError(w, err)
			return
		}
		if seen[repo.FullName] {
			writeError(w, badRequest("repos must not list %s twice", repo.FullName))
			return
		}
		seen[repo.FullName] = true
		repos = append(repos, store.Repo{FullName: repo.FullName, DefaultBranch: repo.DefaultBranch})
	}

	d := daemonFrom(r.Context())
	if err := s.store.ReplaceDaemonRepos(r.Context(), d.ID, name, req.Version, repos); err != nil {
		writeError(w, err)
		return
	}

	if name == "" {
		name = d.Name
	}
	seenAt := time.Now()
	writeJSON(w, http.StatusOK, map[string]any{"daemon": daemonPayload{ID: d.ID.String(), Name: name, Version: req.Version, CreatedAt: d.CreatedAt.UTC().Format(time.RFC3339), LastSeenAt: formatNullableTime(&seenAt), Online: true, Repos: toRepoPayloads(repos)}})
}

// handleDaemonClaim hands this daemon its next run, or 204 when there is nothing
// to do. It also requeues runs abandoned by a dead daemon and refreshes this
// daemon's liveness, so an idle poll still keeps the account showing online.
func (s *Server) handleDaemonClaim(w http.ResponseWriter, r *http.Request) {
	d := daemonFrom(r.Context())
	run, err := s.store.ClaimRun(r.Context(), d.ID, d.UserID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"run": toRunDetailPayload(*run)})
}

// handleDaemonProgress records a heartbeat and doubles as the cancel channel: it
// answers 200 whenever the run belongs to this daemon's user, and accepted false
// tells the daemon the run was canceled, reclaimed or reassigned and it must stop.
// A 409 here would be indistinguishable from a transport failure, which is why
// the guard result rides in the body instead.
func (s *Server) handleDaemonProgress(w http.ResponseWriter, r *http.Request) {
	runID, err := parseUUIDParam(chi.URLParam(r, "runID"), "runId")
	if err != nil {
		writeError(w, err)
		return
	}

	var req daemonProgressRequest
	if err := decodeJSON(w, r, maxSmallBody, &req); err != nil {
		writeError(w, err)
		return
	}
	if !oneOf(req.Phase, store.RunPhaseQueued, store.RunPhaseClaimed, store.RunPhaseCloning, store.RunPhaseCoding, store.RunPhaseChecks, store.RunPhasePushing, store.RunPhasePR) {
		writeError(w, badRequest("phase must be one of queued, claimed, cloning, coding, checks, pushing, pr"))
		return
	}
	if req.TokensUsed < 0 {
		writeError(w, badRequest("tokensUsed must not be negative"))
		return
	}
	if strings.ContainsRune(req.ProgressLog, 0) {
		writeError(w, badRequest("progressLog must not contain a NUL byte"))
		return
	}

	d := daemonFrom(r.Context())
	l, err := s.store.SaveRunProgress(r.Context(), runID, d.ID, d.UserID, req.Phase, tailBytes(req.ProgressLog, maxProgressLogBytes), req.TokensUsed)
	if err != nil {
		writeError(w, storeError(err, "no such run", "", "", "", ""))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"accepted": l.Accepted, "status": l.Status, "phase": l.Phase, "attempts": l.Attempts, "maxAttempts": l.MaxAttempts})
}

// handleDaemonComplete parks a run at pr_ready. A complete that races a cancel
// loses the running guard and returns 409, leaving the run canceled.
func (s *Server) handleDaemonComplete(w http.ResponseWriter, r *http.Request) {
	runID, err := parseUUIDParam(chi.URLParam(r, "runID"), "runId")
	if err != nil {
		writeError(w, err)
		return
	}

	var req daemonCompleteRequest
	if err := decodeJSON(w, r, maxSmallBody, &req); err != nil {
		writeError(w, err)
		return
	}
	if len(req.PRURL) > maxPRURLBytes || !prURLPattern.MatchString(req.PRURL) {
		writeError(w, badRequest("prUrl must be a github.com pull request url"))
		return
	}
	if req.TokensUsed < 0 {
		writeError(w, badRequest("tokensUsed must not be negative"))
		return
	}

	l, err := s.store.CompleteRun(r.Context(), runID, daemonFrom(r.Context()).ID, req.PRURL, req.TokensUsed)
	if err != nil {
		writeError(w, storeError(err, "no such run", "run_conflict", "this run is no longer yours to finish", "", ""))
		return
	}
	writeLifecycle(w, *l)
}

// handleDaemonFail reports work the daemon could not finish. An auth failure parks
// the run immediately without spending an attempt, because retrying cannot help
// until the user fixes a credential; every other outcome spends one and requeues
// until the ceiling is reached.
func (s *Server) handleDaemonFail(w http.ResponseWriter, r *http.Request) {
	runID, err := parseUUIDParam(chi.URLParam(r, "runID"), "runId")
	if err != nil {
		writeError(w, err)
		return
	}

	req, err := decodeOutcomeRequest(w, r, store.RunOutcomeAuth, store.RunOutcomeError, store.RunOutcomeMaxTurns, store.RunOutcomeChecks)
	if err != nil {
		writeError(w, err)
		return
	}

	l, err := s.store.FailRun(r.Context(), runID, daemonFrom(r.Context()).ID, req.Outcome, req.ErrorLog, req.TokensUsed, req.Outcome == store.RunOutcomeAuth)
	if err != nil {
		writeError(w, storeError(err, "no such run", "run_conflict", "this run is no longer yours to finish", "", ""))
		return
	}
	writeLifecycle(w, *l)
}

// handleDaemonRelease hands a run back unfinished because the daemon ran out of
// quota or wall clock. No attempt is spent — nothing was wrong with the work —
// and the progress log survives so the next claim resumes from it.
func (s *Server) handleDaemonRelease(w http.ResponseWriter, r *http.Request) {
	runID, err := parseUUIDParam(chi.URLParam(r, "runID"), "runId")
	if err != nil {
		writeError(w, err)
		return
	}

	req, err := decodeOutcomeRequest(w, r, store.RunOutcomeQuota, store.RunOutcomeDeadline)
	if err != nil {
		writeError(w, err)
		return
	}

	l, err := s.store.ReleaseRun(r.Context(), runID, daemonFrom(r.Context()).ID, req.Outcome, req.ErrorLog, req.TokensUsed)
	if err != nil {
		writeError(w, storeError(err, "no such run", "run_conflict", "this run is no longer yours to finish", "", ""))
		return
	}
	writeLifecycle(w, *l)
}
